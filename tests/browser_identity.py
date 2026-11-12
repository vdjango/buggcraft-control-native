"""Native identity HTTP + PostgreSQL, migration and real TLS SMTP regressions."""
import base64
import concurrent.futures
import hashlib
import http.cookiejar
import json
import queue
import re
import secrets
import socketserver
import ssl
import struct
import subprocess
import threading
import time
import unittest
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from integration import Environment, EXE, Client, write_private


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def public(key):
    numbers = key.public_key().public_numbers()
    return dict(kty='EC', crv='P-256', x=encoded(numbers.x.to_bytes(32, 'big')),
                y=encoded(numbers.y.to_bytes(32, 'big')))


def signature(key, message):
    r, s = utils.decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return encoded(r.to_bytes(32, 'big')+s.to_bytes(32, 'big'))


class BrowserClient:
    def __init__(self, environment):
        self.base = environment.base
        self.csrf = ''
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=environment.public.context),
            urllib.request.HTTPCookieProcessor(self.cookies))

    def call(self, path, body=None, expected=200, origin=None):
        headers = {'Content-Type': 'application/json', 'X-Account-CSRF': self.csrf,
                   'Origin': self.base if origin is None else origin}
        request = urllib.request.Request(self.base+path,
            None if body is None else canonical(body), headers=headers)
        try:
            with self.opener.open(request, timeout=20) as response:
                status, data = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            status, data = error.code, json.load(error)
        if expected is not None and status != expected:
            raise AssertionError(f'{path}: {status} != {expected}: {data}')
        return (status, data) if expected is None else data

    def login(self, identifier, key):
        challenge = self.call('/api/account/challenge', dict(account=identifier))
        result = self.call('/api/account/login', dict(nonce=challenge['nonce'],
            signature=signature(key, challenge['message'].encode())))
        self.csrf = result['csrf']
        return result


class SmtpFixture:
    """TLS-only SMTP peer. Authentication and DATA travel over verified TLS."""
    def __init__(self, environment):
        owner = self
        self.messages = queue.Queue()
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b'220 localhost test SMTP\r\n')
                while line := self.rfile.readline(4096):
                    command = line.decode().strip()
                    if command.startswith('EHLO'):
                        self.wfile.write(b'250-localhost\r\n250 AUTH PLAIN\r\n')
                    elif command.startswith('AUTH PLAIN'):
                        if command == 'AUTH PLAIN':
                            self.wfile.write(b'334 \r\n')
                            payload=self.rfile.readline(4096).strip()
                        else:
                            payload=command.split(' ',2)[2].encode()
                        valid=base64.b64decode(payload)==b'\x00sender@example.com\x00test-only'
                        self.wfile.write(b'235 authenticated\r\n' if valid else b'535 rejected\r\n')
                    elif command.startswith(('MAIL FROM:', 'RCPT TO:', 'RSET')):
                        self.wfile.write(b'250 accepted\r\n')
                    elif command == 'DATA':
                        self.wfile.write(b'354 continue\r\n')
                        message = b''
                        while (part := self.rfile.readline(4096)) not in (b'.\r\n', b''):
                            message += part
                        owner.messages.put(message.decode())
                        self.wfile.write(b'250 queued\r\n')
                    elif command == 'QUIT':
                        self.wfile.write(b'221 bye\r\n')
                        return
                    else:
                        self.wfile.write(b'500 unsupported\r\n')
        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(environment.path/'tls.pem', environment.path/'tls-key.pem')
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class BrowserIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Environment()
        cls.addClassCleanup(cls.env.close)
        cls.smtp = SmtpFixture(cls.env)
        cls.addClassCleanup(cls.smtp.close)
        cls.issuer = ed25519.Ed25519PrivateKey.generate()
        issuer_public = cls.issuer.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        cls.home = hashlib.sha256(issuer_public.encode()).hexdigest()[:32]
        write_private(cls.env.path/'issuer.pem', cls.issuer.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        write_private(cls.env.path/'audience', 'a'*64)
        write_private(cls.env.path/'smtp.json', json.dumps(dict(required=False, host='localhost',
            port=cls.smtp.server.server_address[1], implicit_tls=True, username='sender@example.com',
            password='test-only', ca_file=str(cls.env.path/'tls.pem'))))
        cls.env.config['browser'] = dict(origin=cls.env.base, assets=str(cls.env.path),
            issuer_key='issuer.pem', issuer_public=issuer_public, audience_key_file='audience',
            smtp_file='smtp.json', registration_open=True)
        write_private(cls.env.path/'config.json', json.dumps(cls.env.config))
        cls.owner = ec.generate_private_key(ec.SECP256R1())
        cls.account = '1'*32+'.'+cls.home
        certificate = dict(uid='1'*32, home=cls.home, home_key=issuer_public, username='ExistingUser',
                           public_key=public(cls.owner), created=time.time())
        def ssh_field(value):
            return struct.pack('>I', len(value))+value
        issuer_signature = encoded(ssh_field(b'ssh-ed25519')+ssh_field(cls.issuer.sign(canonical(certificate))))
        state = dict(account=cls.account, revision=2, box=dict(iterations=600000,
            salt=encoded(secrets.token_bytes(16)), iv=encoded(secrets.token_bytes(12)),
            ciphertext=encoded(secrets.token_bytes(64))))
        record = dict(certificate=certificate, issuer_signature=issuer_signature, state=state,
                      signature=signature(cls.owner, canonical(state)))
        cls.device = ec.generate_private_key(ec.SECP256R1())
        def device_record(identifier, expired=False):
            now = int(time.time())-86400*200 if expired else int(time.time())
            grant = dict(a=cls.account, i=cls.home, n='n'*24, p='buggcraft-launcher-device-v1',
                o=cls.env.base, r=identifier, b=now, e=now+86400*180, d=public(cls.device))
            return dict(grant=grant, signature=signature(cls.owner, canonical(grant)), name='Migrated device',
                        last_used=float(now), revoked=expired)
        cls.import_snapshot = dict(version=1, accounts=[dict(record=record)],
            devices={'2'*32: device_record('2'*32), '3'*32: device_record('3'*32, True)},
            mailboxes=[dict(mailbox='f'*64, account=cls.account, preferred=True)])
        write_private(cls.env.path/'snapshot.json', json.dumps(cls.import_snapshot))
        cls.env.process.terminate()
        cls.env.process.wait(timeout=15)
        cls.import_command = [str(EXE), '--config', str(cls.env.path/'config.json'),
                              '--import-browser', str(cls.env.path/'snapshot.json')]
        result = subprocess.run(cls.import_command, check=True, capture_output=True, text=True)
        assert json.loads(result.stdout) == dict(accounts=1, devices=2, mailboxes=1)
        cls.env.start()

    def client(self):
        return BrowserClient(self.env)

    def sql(self, statement):
        return subprocess.run(['psql', (self.env.path/'db').read_text(), '-v', 'ON_ERROR_STOP=1',
            '-At', '-c', statement], check=True, capture_output=True, text=True).stdout.strip()

    def register(self, name):
        client=self.client();key=ec.generate_private_key(ec.SECP256R1())
        enrollment=client.call('/api/account/enroll',{})
        state=dict(self.import_snapshot['accounts'][0]['record']['state'])
        state.update(account=enrollment['account'],revision=1)
        client.call('/api/account/register',dict(nonce=enrollment['nonce'],username=name,
            public_key=public(key),state=state,proof=signature(key,enrollment['message'].encode()),
            signature=signature(key,canonical(state)),password_length=6,
            password_digest=hashlib.sha256(b'7vq!9x').hexdigest()),201)
        return enrollment['account'],key

    def test_existing_identity_and_revision_survive_import(self):
        client = self.client()
        self.assertEqual(client.login('ExistingUser', self.owner)['account'], self.account)
        me = client.call('/api/account/me')
        self.assertEqual(me['revision'], 2)
        devices = client.call('/api/launcher/devices')['devices']
        self.assertEqual(len(devices), 2)
        self.assertFalse(next(d for d in devices if d['id'] == '3'*32)['active'])
        result = subprocess.run(self.import_command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(client.call('/api/account/me')['account'], self.account)

    def test_static_landscape_is_bounded_and_not_a_general_file_endpoint(self):
        image = self.env.path/'vue-bugg-landscape-test.webp'
        image.write_bytes(b'RIFF-test-WEBP')
        with urllib.request.urlopen(self.env.base+'/'+image.name, context=self.env.public.context) as response:
            self.assertEqual(response.headers.get_content_type(), 'image/webp')
            self.assertEqual(response.read(), image.read_bytes())
        for path in ['/snapshot.json', '/issuer.pem', '/vue-other-test.webp', '/assets/../issuer.pem']:
            with self.assertRaises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(self.env.base+path, context=self.env.public.context)
            self.assertEqual(failure.exception.code, 404)

    def test_failed_signature_burns_nonce(self):
        client = self.client()
        challenge = client.call('/api/account/challenge', dict(account=self.account))
        client.call('/api/account/login', dict(nonce=challenge['nonce'], signature='AA'), 401)
        client.call('/api/account/login', dict(nonce=challenge['nonce'],
            signature=signature(self.owner, challenge['message'].encode())), 410)

    def test_cookie_csrf_origin_and_logout(self):
        client = self.client()
        client.login(self.account, self.owner)
        client.call('/api/account/logout', {}, 403, origin='https://untrusted.example')
        csrf, client.csrf = client.csrf, 'wrong'
        client.call('/api/account/logout', {}, 403)
        client.csrf = csrf
        client.call('/api/account/logout', {})
        client.call('/api/account/me', expected=401)

    def test_email_tls_delivery_and_one_use(self):
        client = self.client()
        client.login(self.account, self.owner)
        ticket = client.call('/api/account/email-code', dict(email='player@example.com', purpose='link'))
        message = self.smtp.messages.get(timeout=2)
        code = re.search(r'code: (\d{6})', message)[1]
        body = dict(ticket=ticket['ticket'], code=code)
        accounts = client.call('/api/account/email-accounts', body)['accounts']
        self.assertEqual(accounts[0]['account'], self.account)
        client.call('/api/account/email-accounts', body, 410)
        client.call('/api/account/email-code', dict(email='player@example.com', purpose='link'), 429)

    def test_refresh_race_cannot_revive_revocation(self):
        client = self.client()
        client.login(self.account, self.owner)
        identifier = '2'*32
        message = client.call('/api/launcher/challenge', dict(id=identifier))['message']
        def refresh():
            return self.client().call('/api/launcher/refresh', dict(nonce=message['nonce'],
                signature=signature(self.device, canonical(message))), expected=None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(refresh)
            client.call('/api/launcher/revoke', dict(id=identifier))
            self.assertIn(future.result()[0], (200, 401))
        message = client.call('/api/launcher/challenge', dict(id=identifier))['message']
        client.call('/api/launcher/refresh', dict(nonce=message['nonce'],
            signature=signature(self.device, canonical(message))), 401)

    def test_memories_are_private_and_merge_heartbeats(self):
        browser=self.client();browser.login(self.account,self.owner)
        self.client().call('/api/account/memories',expected=401)
        message=browser.call('/api/launcher/challenge',dict(id='2'*32))['message']
        profile=browser.call('/api/launcher/refresh',dict(nonce=message['nonce'],
            signature=signature(self.device,canonical(message))))['profile']
        delegate=self.import_snapshot['devices']['2'*32]
        challenge=self.env.public.call('identity/challenge',dict(certificate=profile['control']['certificate'],
            issuer_signature=profile['control']['issuer_signature'],device_id='2'*32,
            device_grant=delegate['grant'],delegation_signature=delegate['signature']))
        grant=self.env.public.call('identity/prove',dict(challenge_id=challenge['challenge_id'],
            signature=signature(self.device,challenge['message'].encode())))
        player=Client(self.env.base,self.env.path/'tls.pem',grant['token'])
        first=player.call('presence/open',dict(idempotency_key='memory-one'))
        second=player.call('presence/open',dict(idempotency_key='memory-two'))
        self.sql("UPDATE account_activity SET last_seen=floor(extract(epoch FROM clock_timestamp()))::bigint-10,lease_until=floor(extract(epoch FROM clock_timestamp()))::bigint+30 WHERE account_id='"+self.account+"'")
        player.call('presence/refresh',dict(session_id=first['session_id'],sequence=1))
        player.call('presence/refresh',dict(session_id=second['session_id'],sequence=1))
        memories=browser.call('/api/account/memories')
        self.assertTrue(10<=memories['online_seconds']<=12,memories)
        self.assertEqual(memories['multiplayer_seconds'],0)
        self.assertEqual(sum(day['online_seconds'] for day in memories['days']),memories['online_seconds'])
        self.sql("UPDATE account_activity SET last_seen=floor(extract(epoch FROM clock_timestamp()))::bigint-600,lease_until=0 WHERE account_id='"+self.account+"'")
        player.call('presence/refresh',dict(session_id=first['session_id'],sequence=2))
        self.assertEqual(browser.call('/api/account/memories')['online_seconds'],memories['online_seconds'])
        other,key=self.register('MemoryPrivacy');private=self.client();private.login(other,key)
        hidden=private.call('/api/account/memories?account='+self.account)
        self.assertEqual(hidden['online_seconds'],0)
        self.assertEqual(hidden['companions'],[])
        self.assertNotIn(self.account,json.dumps(hidden))
        player.call('presence/close',dict(session_id=first['session_id'],sequence=3))
        player.call('presence/close',dict(session_id=second['session_id'],sequence=2))

    def test_registration_policy_and_reserved_names(self):
        client=self.client()
        policy=client.call('/api/account/policy')
        self.assertEqual(policy['minimum_length'],6)
        self.assertIn('123456',policy['blocked_passwords'])
        for name,password,code in [('Admin','7vQ!9x','reserved_name'),('realplayer','123456','weak_password')]:
            enroll=client.call('/api/account/enroll',{})
            status,result=client.call('/api/account/register',dict(nonce=enroll['nonce'],username=name,
                password_length=len(password),password_digest=hashlib.sha256(password.lower().encode()).hexdigest()),expected=None)
            self.assertEqual(status,400)
            self.assertIsInstance(result['error'],str)

    def test_zz_mailbox_recovery_preserves_identity_and_revokes_sessions(self):
        client=self.client();client.login(self.account,self.owner)
        def send(email,purpose):
            ticket=client.call('/api/account/email-code',dict(email=email,purpose=purpose))
            code=re.search(r'code: (\d{6})',self.smtp.messages.get(timeout=2))[1]
            return ticket,code
        ticket,code=send('recover@example.com','link')
        client.call('/api/account/email-accounts',dict(ticket=ticket['ticket'],code=code))
        # Only advance the test rate bucket, not production time or constraints.
        self.sql("UPDATE rate_buckets SET window_id=0")
        ticket,code=send('recover@example.com','recovery')
        data=client.call('/api/account/recovery-verify',dict(ticket=ticket['ticket'],nonce=ticket['nonce'],code=code))
        self.assertEqual(data['accounts'][0]['account'],self.account)
        client.call('/api/account/recovery-verify',dict(ticket=ticket['ticket'],nonce=ticket['nonce'],code=code),410)
        replacement=ec.generate_private_key(ec.SECP256R1())
        state=dict(self.import_snapshot['accounts'][0]['record']['state']);state['revision']=3
        payload=dict(grant=data['grant'],account=self.account,public_key=public(replacement),state=state,
            signature=signature(replacement,canonical(state)),password_length=6,
            password_digest=hashlib.sha256(b'7vq!9x').hexdigest())
        result=client.call('/api/account/recovery-reset',payload)
        self.assertTrue(result['ok'])
        client.call('/api/account/me',expected=401)
        client.call('/api/account/recovery-reset',payload,410)
        self.assertEqual(client.login('ExistingUser',replacement)['account'],self.account)
        old=self.client();challenge=old.call('/api/account/challenge',dict(account=self.account))
        old.call('/api/account/login',dict(nonce=challenge['nonce'],signature=signature(self.owner,challenge['message'].encode())),401)
        self.assertEqual(self.sql("SELECT count(*) FROM browser_devices WHERE NOT (body->>'revoked')::boolean"),'0')
        self.assertEqual(self.sql("SELECT count(*) FROM friendships WHERE state='accepted'"),'1')

    def test_signed_social_import_is_idempotent_and_atomic(self):
        target,target_key=self.register('Companion')
        now=int(time.time())
        def event(actor,key,to,op,identifier,at,reference=None):
            delegate=ec.generate_private_key(ec.SECP256R1())
            grant=dict(a=actor,i=self.home,n='x'*24,p='buggcraft-launcher-device-v1',
                o=self.env.base,r='4'*32,b=now-100,e=now+3600,d=public(delegate))
            action=dict(id=identifier,op=op,target=to,at=at)
            if reference:action['ref']=reference
            return dict(grant=grant,proof=signature(key,canonical(grant)),action=action,
                signature=signature(delegate,canonical(action)))
        request=event(self.account,self.owner,target,'request','a'*32,now-20)
        accept=event(target,target_key,self.account,'accept','b'*32,now-10,'a'*32)
        path=self.env.path/'social.json'
        command=[str(EXE),'--config',str(self.env.path/'config.json'),'--import-social',str(path)]
        write_private(path,json.dumps([request,accept]))
        first=json.loads(subprocess.run(command,check=True,capture_output=True,text=True).stdout)
        self.assertEqual(first,dict(events_added=2,accepted_pairs=1,pending_pairs=0))
        second=json.loads(subprocess.run(command,check=True,capture_output=True,text=True).stdout)
        self.assertEqual(second['events_added'],0)
        self.assertEqual(self.sql("SELECT count(*) FROM friendships WHERE state='accepted'"),'1')
        # Invalid later events cannot partially change the import journal.
        invalid=event(self.account,self.owner,target,'remove','c'*32,now)
        invalid['signature']='AA'
        write_private(path,json.dumps([invalid]))
        self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
        self.assertEqual(self.sql('SELECT count(*) FROM legacy_social_import'),'2')
        self.sql("UPDATE friendships SET state='rejected'")
        write_private(path,json.dumps([request,accept]))
        subprocess.run(command,check=True,capture_output=True)
        self.assertEqual(self.sql("SELECT count(*) FROM friendships WHERE state='accepted'"),'0')
        self.sql("UPDATE friendships SET state='accepted'")

    def test_social_import_rejects_missing_certificate(self):
        path=self.env.path/'social-invalid.json'
        write_private(path,json.dumps([dict(grant=dict(a=self.account),action=dict(target=self.account,op='request'))]))
        result=subprocess.run([str(EXE),'--config',str(self.env.path/'config.json'),'--import-social',str(path)],capture_output=True)
        self.assertNotEqual(result.returncode,0)

    def test_web_sessions_are_owned_and_show_client_details(self):
        first=self.client();second=self.client()
        first.login(self.account,self.owner);second.login(self.account,self.owner)
        sessions=first.call('/api/account/sessions')['sessions']
        self.assertEqual(sum(row['current'] for row in sessions),1)
        other=next(row for row in sessions if not row['current'])
        self.assertIn('system',other['client'])
        first.call('/api/account/session-revoke',dict(id=other['id']))
        first.call('/api/account/session-revoke',dict(id=other['id']),404)


if __name__ == '__main__':
    unittest.main(verbosity=2)

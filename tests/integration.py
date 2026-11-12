"""Real TLS/WSS + isolated PostgreSQL integration tests. No production endpoint is contacted."""
import base64
import concurrent.futures
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get("CONTROL_BINARY", ROOT / "build" / "buggcraft-control"))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_private(path, content):
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                       x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    write_private(directory/"tls.pem", cert.public_bytes(serialization.Encoding.PEM).decode())
    write_private(directory/"tls-key.pem", key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


class Client:
    def __init__(self, base, ca, token=""):
        self.base, self.token = base, token
        self.context = ssl.create_default_context(cafile=str(ca))

    def call(self, operation, body=None, expected=200):
        request = urllib.request.Request(self.base+"/v1/"+operation,
            json.dumps(body or {}, separators=(",", ":")).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer "+self.token})
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=20) as response:
                status, result = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            status, result = error.code, json.load(error)
        if expected is not None and status != expected:
            raise AssertionError(f"{operation}: expected {expected}, received {status}: {result}")
        return result if expected is not None else (status, result)


class NodeProof:
    def __init__(self, key, directory):
        owner = self
        self.key = key

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/.well-known/buggcraft-node-proof" or length > 4096:
                    self.send_error(400)
                    return
                body = json.loads(self.rfile.read(length))
                message = "buggcraft-node-proof-v1\n"+body["nonce"]+"\n"+body["endpoint"]
                output = json.dumps({"signature": owner.key.sign(message.encode()).hex()}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory/"tls.pem", directory/"tls-key.pem")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.endpoint = "127.0.0.1:"+str(self.server.server_port)
        self.game = socket.socket()
        self.game.bind(("127.0.0.1", 0))
        self.game.listen()
        self.game.settimeout(0.2)
        self.game_endpoint = "127.0.0.1:"+str(self.game.getsockname()[1])
        self.stopping = threading.Event()
        def accept_game():
            while not self.stopping.is_set():
                try:
                    connection, _ = self.game.accept()
                    connection.close()
                except socket.timeout:
                    pass
        self.game_thread = threading.Thread(target=accept_game, daemon=True)
        self.game_thread.start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.stopping.set()
        self.game_thread.join()
        self.game.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class WebSocketClient:
    """Small wire fixture to test the production Beast implementation without a second server library."""
    def __init__(self, client):
        from urllib.parse import urlsplit
        url = urlsplit(client.base)
        raw = socket.create_connection((url.hostname, url.port), timeout=10)
        self.socket = client.context.wrap_socket(raw, server_hostname=url.hostname)
        self.file = self.socket.makefile("rb")
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        request = (f"GET /v1/channel HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {client.token}\r\n\r\n")
        self.socket.sendall(request.encode())
        status = self.file.readline()
        if not status.startswith(b"HTTP/1.1 101"):
            raise AssertionError("WebSocket upgrade failed: "+status.decode())
        headers = {}
        while True:
            line = self.file.readline()
            if line == b"\r\n":
                break
            k, v = line.decode().split(":", 1)
            headers[k.lower()] = v.strip()
        expected = base64.b64encode(hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != expected:
            raise AssertionError("Invalid WebSocket accept")

    def send_frame(self, payload, opcode=1):
        mask = secrets.token_bytes(4)
        size = len(payload)
        header = bytes([0x80 | opcode, 0x80 | size]) if size < 126 else bytes([0x80 | opcode, 0xfe])+struct.pack(">H", size)
        self.socket.sendall(header+mask+bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))

    def send(self, path, body, request_id="test"):
        self.send_frame(json.dumps({"path": "/v1/"+path, "body": body, "request_id": request_id}).encode())

    def receive(self):
        while True:
            head = self.file.read(2)
            if len(head) != 2:
                raise EOFError("Channel closed")
            opcode, size = head[0] & 15, head[1] & 127
            if size == 126:
                size = struct.unpack(">H", self.file.read(2))[0]
            elif size == 127:
                size = struct.unpack(">Q", self.file.read(8))[0]
            if size > 262144:
                raise AssertionError("Unbounded channel response")
            data = self.file.read(size)
            if opcode == 9:
                self.send_frame(data, 10)
            elif opcode == 1:
                return json.loads(data)
            else:
                raise EOFError("Channel closed")

    def close(self):
        self.file.close()
        self.socket.close()


class Environment:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="buggcraft-control-test-")
        self.path = Path(self.temp.name)
        self.proofs = []
        self.process = None
        self.replicas = []
        self.pg = None
        self.pg_bin = None
        self.log = (self.path/"service.log").open("w+")
        certificate(self.path)
        key = ed25519.Ed25519PrivateKey.generate()
        write_private(self.path/"signing.pem", key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        self.admin_token = secrets.token_hex(32)
        write_private(self.path/"admin", self.admin_token)
        conninfo = os.environ.get("CONTROL_TEST_DATABASE")
        if not conninfo:
            versions = sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)
            self.pg_bin = versions[0]
            self.pg = self.path/"postgres"
            subprocess.run([str(self.pg_bin/"initdb"), "-D", str(self.pg), "-A", "trust", "--no-locale"], check=True, stdout=subprocess.DEVNULL)
            port = free_port()
            subprocess.run([str(self.pg_bin/"pg_ctl"), "-D", str(self.pg), "-l", str(self.path/"postgres.log"),
                            "-o", f"-k {self.path} -h '' -p {port}", "-w", "start"], check=True, stdout=subprocess.DEVNULL)
            conninfo = f"host={self.path} port={port} dbname=postgres connect_timeout=3"
        write_private(self.path/"db", conninfo)
        port = free_port()
        self.config = {"listen": "127.0.0.1", "port": port, "tls_certificate": "tls.pem", "tls_key": "tls-key.pem",
                       "signing_key": "signing.pem", "database_file": "db", "admin_token_file": "admin",
                       "schema_file": str(ROOT/"sql/001-initial.sql"), "allow_loopback_nodes": True,
                       "heartbeat_limit": 10000, "node_lease_seconds": 120, "queue_limit": 256,
                       "max_connections": 512}
        self.config["json_implementation"] = os.environ.get("CONTROL_JSON_BACKEND", "auto")
        write_private(self.path/"config.json", json.dumps(self.config))
        self.base = f"https://127.0.0.1:{port}"
        self.public = Client(self.base, self.path/"tls.pem")
        self.admin = Client(self.base, self.path/"tls.pem", self.admin_token)
        self.credential = secrets.token_hex(32)
        try:
            self.start()
            self.admin.call("admin/credential", {"id": "test", "credential": self.credential, "pool": "community"})
        except BaseException:
            self.close()
            raise

    def start(self):
        self.process = subprocess.Popen([str(EXE), "--config", str(self.path/"config.json")], stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                self.log.flush()
                raise RuntimeError((self.path/"service.log").read_text())
            try:
                self.public.call("health")
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise RuntimeError("Service startup timeout")

    def restart(self):
        self.process.terminate()
        self.process.wait(timeout=15)
        self.start()

    def replica(self):
        config = dict(self.config, port=free_port())
        file = self.path/f"replica-{config['port']}.json"
        write_private(file, json.dumps(config))
        process = subprocess.Popen([str(EXE), "--config", str(file)], stdout=self.log, stderr=self.log)
        self.replicas.append(process)
        client = Client(f"https://127.0.0.1:{config['port']}", self.path/"tls.pem")
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Replica exited during startup")
            try:
                client.call("health")
                return client
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        raise RuntimeError("Replica startup timeout")

    def identity(self, device="desktop", key=None):
        key = key or ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        challenge = self.public.call("identity/challenge", {"public_key": public, "device_id": device})
        proof = {"challenge_id": challenge["challenge_id"], "signature": key.sign(challenge["message"].encode()).hex()}
        grant = self.public.call("identity/prove", proof)
        client = Client(self.base, self.path/"tls.pem", grant["token"])
        client.account_id = grant["id"]
        return client, grant, key, proof

    def node(self, region="cn-south", slots=128, credential=None):
        key = ed25519.Ed25519PrivateKey.generate()
        proof = NodeProof(key, self.path)
        self.proofs.append(proof)
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        payload = {"public_key": public, "credential": credential or self.credential, "region": region,
                   "operator": "test", "endpoint": proof.game_endpoint, "slots": slots, "bandwidth": 1000000000, "protocol": 1}
        challenge = self.public.call("enrollment/challenge", payload)
        signed = {"challenge_id": challenge["challenge_id"], "signature": key.sign(challenge["message"].encode()).hex()}
        grant = self.public.call("enrollment/prove", signed)
        client = Client(self.base, self.path/"tls.pem", grant["token"])
        client.call("node/activate", {"proof_endpoint": proof.endpoint})
        client.call("node/heartbeat", {"sequence": 1, "observed_slots": 0, "observed_bandwidth": 0})
        return client, grant, key, payload, signed

    def reserve(self, player, node_id, room=None, idem=None):
        candidates = player.call("placement/candidates", {"region": "cn-south", "operator": "test", "nearby": ["cn-east"]})
        if not any(item["node_id"] == node_id for item in candidates["candidates"]):
            raise AssertionError("Expected test node missing from candidate set")
        body = {"idempotency_key": idem or secrets.token_hex(8), "room_id": room or secrets.token_hex(12), "intent": "new",
                "probe_token": candidates["probe_token"], "measurements": [{"node_id": node_id, "rtt_ms": 5}], "slots": 1, "bandwidth": 1000}
        return player.call("placement/reserve", body), body

    def close(self):
        for process in self.replicas:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=15)
        for proof in self.proofs:
            proof.close()
        if self.pg:
            subprocess.run([str(self.pg_bin/"pg_ctl"), "-D", str(self.pg), "-m", "fast", "-w", "stop"], check=True, stdout=subprocess.DEVNULL)
        self.log.close()
        evidence = os.environ.get("CONTROL_TEST_LOG_DIR")
        if evidence:
            destination = Path(evidence)
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.path/"service.log", destination/"service.log")
            (destination/"exit.json").write_text(json.dumps({"primary_exit": self.process.poll() if self.process else None}), encoding="utf-8")
        self.temp.cleanup()


class ControlIntegration(unittest.TestCase):
    def test_21_room_directory_uses_published_policy_and_current_host(self):
        host, _, *_ = self.env.identity()
        guest, _, *_ = self.env.identity()
        secret = secrets.token_urlsafe(32)
        room_id = hashlib.sha256(secret.encode()).hexdigest()[:32]
        allocation, _ = self.env.reserve(host, self.west_grant['id'], room=room_id)
        publish = dict(room_id=room_id, reservation_id=allocation['reservation_id'],
                       room_epoch=allocation['room_epoch'], secret=secret,
                       room=dict(title='Public adventure', public=True, require_invite=False,
                                 availability='waiting', game=dict(version='1.21.1', loader='Fabric'),
                                 connections=0, capacity=8))
        try:
            self.assertNotIn(room_id, [r['id'] for r in host.call('room/list')['rooms']])
            host.call('room/publish', publish, expected=404)  # Pending admission is not a lobby.
            self.west.call('placement/confirm', dict(reservation_id=allocation['reservation_id'], ticket=allocation['ticket']))
            self.assertNotIn(room_id, [r['id'] for r in host.call('room/list')['rooms']])
            guest.call('room/publish', publish, expected=404)
            host.call('room/publish', dict(publish, room_epoch=999), expected=409)
            host.call('room/publish', dict(publish, secret=secrets.token_urlsafe(32)), expected=400)
            host.call('room/publish', publish)
            rows = guest.call('room/list', dict(query='adventure'))['rooms']
            entry = next(r for r in rows if r['id'] == room_id)
            self.assertEqual(entry['title'], 'Public adventure')
            self.assertFalse(entry['require_invite'])
            self.assertEqual(entry['game']['loader'], 'Fabric')
            self.assertEqual(entry['availability'], 'waiting')
            self.assertNotIn('secret', entry)
            self.assertNotIn(room_id, [r['id'] for r in guest.call('room/list', dict(query='absent'))['rooms']])
            for actor in (host, guest):
                self.assertEqual(actor.call('room/resolve', dict(room_id=room_id))['secret'], secret)
            joined = guest.call('placement/reserve', dict(idempotency_key=secrets.token_hex(8),
                intent='join', room_id=room_id, secret=secret, slots=1, bandwidth=1000))
            self.assertEqual(joined['node_id'], self.west_grant['id'])
            guest.call('placement/release', dict(reservation_id=joined['reservation_id']))
            publish['room']['require_invite'] = True
            host.call('room/publish', publish)
            self.assertTrue(next(r for r in guest.call('room/list')['rooms'] if r['id'] == room_id)['require_invite'])
            guest.call('room/resolve', dict(room_id=room_id), expected=403)
            guest.call('placement/reserve', dict(idempotency_key=secrets.token_hex(8), intent='join',
                room_id=room_id, slots=1, bandwidth=1000), expected=403)
            # A copied invitation is itself a capability; no social event is required.
            joined = guest.call('placement/reserve', dict(idempotency_key=secrets.token_hex(8),
                intent='join', room_id=room_id, secret=secret, slots=1, bandwidth=1000))
            guest.call('placement/release', dict(reservation_id=joined['reservation_id']))
            publish['room']['public'] = False
            host.call('room/publish', publish)
            self.assertNotIn(room_id, [r['id'] for r in host.call('room/list')['rooms']])
        finally:
            host.call('placement/release', dict(reservation_id=allocation['reservation_id']))
        guest.call('room/resolve', dict(room_id=room_id), expected=404)

    def test_22_expired_host_is_not_listed_or_resolvable(self):
        host, _, *_ = self.env.identity()
        secret = secrets.token_urlsafe(32)
        room_id = hashlib.sha256(secret.encode()).hexdigest()[:32]
        allocation, _ = self.env.reserve(host, self.west_grant['id'], room=room_id)
        self.west.call('placement/confirm', dict(reservation_id=allocation['reservation_id'], ticket=allocation['ticket']))
        host.call('room/publish', dict(room_id=room_id, reservation_id=allocation['reservation_id'],
            room_epoch=allocation['room_epoch'], secret=secret, room=dict(title='Expired test',
            public=True, require_invite=False, availability='ready', game={}, connections=0, capacity=8)))
        subprocess.run(['psql', (self.env.path/'db').read_text(), '-v', 'ON_ERROR_STOP=1', '-c',
            "UPDATE reservations SET expires_at=clock_timestamp()-interval '1 second' WHERE id='"+
            allocation['reservation_id']+"'"], check=True, capture_output=True)
        self.assertNotIn(room_id, [r['id'] for r in host.call('room/list')['rooms']])
        host.call('room/resolve', dict(room_id=room_id), expected=404)
        host.call('placement/release', dict(reservation_id=allocation['reservation_id']))

    @classmethod
    def setUpClass(cls):
        cls.env = Environment()
        cls.addClassCleanup(cls.env.close)
        cls.west, cls.west_grant, *_ = cls.env.node()
        cls.east, cls.east_grant, *_ = cls.env.node("cn-east")

    def test_20_public_enrollment_is_optional_scoped_and_revocable(self):
        env = self.env
        env.public.call('enrollment/profile', expected=404)
        token = secrets.token_hex(32)
        write_private(env.path/'public-enrollment', token)
        env.admin.call('admin/credential', dict(id='public-install', credential=token, pool='community'))
        env.config['public_enrollment_credential_file'] = 'public-enrollment'
        write_private(env.path/'config.json', json.dumps(env.config))
        try:
            env.restart()
            profile = env.public.call('enrollment/profile')
            self.assertEqual(set(profile), {'protocol', 'credential', 'signing_public_key'})
            self.assertEqual(profile['credential'], token)
            self.assertEqual(profile['signing_public_key'], env.public.call('health')['signing_public_key'])
            Client(env.base, env.path/'tls.pem', token).call('admin/node', {}, expected=401)
            env.admin.call('admin/credential/revoke', dict(id='public-install'))
            env.public.call('enrollment/profile', expected=503)
            # Even an operator mistake cannot publish administrator authorization.
            write_private(env.path/'public-enrollment', env.admin_token)
            env.admin.call('admin/credential', dict(id='wrong-file', credential=env.admin_token, pool='community'))
            result = env.public.call('enrollment/profile', expected=500)
            self.assertNotIn(env.admin_token, json.dumps(result))
        finally:
            env.config.pop('public_enrollment_credential_file')
            write_private(env.path/'config.json', json.dumps(env.config))
            env.restart()

    def test_19_feedback_durable_private_idempotent(self):
        data = dict(id=secrets.token_hex(16), message='Launcher feedback test', contact='', diagnostics=dict(system='windows'))
        result = self.env.public.call('feedback/submit', data)
        self.assertTrue(result['accepted'])
        self.assertEqual(result, self.env.public.call('feedback/submit', data))
        self.env.public.call('feedback/submit', dict(data, message='different'), 409)
        self.env.public.call('admin/feedback/list', {}, 401)
        self.env.public.call('feedback/submit', dict(data, id=secrets.token_hex(16), diagnostics={'token':'forbidden'}), 400)
        self.env.restart()
        items = self.env.admin.call('admin/feedback/list')['items']
        self.assertEqual(sum(item['id']==data['id'] for item in items), 1)

    def friends(self):
        a, ga, *_ = self.env.identity()
        b, gb, *_ = self.env.identity()
        a.call("social/apply", {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "friend_request"})
        b.call("social/apply", {"event_id": secrets.token_hex(8), "target": ga["id"], "kind": "friend_accept"})
        return a, ga, b, gb

    def test_01_long_credential_registers_distinct_nodes(self):
        self.assertNotEqual(self.west_grant["id"], self.east_grant["id"])
        self.assertNotEqual(self.west.token, self.east.token)
        self.assertNotIn("master_key", self.west_grant)

    def test_02_unauthorized_scopes(self):
        self.env.public.call("placement/candidates", {"region": "cn-south", "operator": "test"}, expected=401)
        self.west.call("admin/node", {"id": self.east_grant["id"], "status": "revoked"}, expected=401)
        self.west.call("presence/open", {"idempotency_key": "no"}, expected=403)

    def test_03_proof_replay_and_epoch(self):
        client, grant, key, proof = self.env.identity()
        retry = self.env.public.call("identity/prove", proof)
        self.assertEqual(grant["epoch"], retry["epoch"])
        other, _, _, _ = self.env.identity(key=key)
        self.env.public.call("identity/prove", proof, expected=409)
        client.call("presence/open", {"idempotency_key": "stale"}, expected=401)
        other.call("presence/open", {"idempotency_key": "current"})

    def test_04_presence_multidevice_sequence(self):
        a, ga, key, _ = self.env.identity("desktop")
        b, _, _, _ = self.env.identity("mobile", key)
        one = a.call("presence/open", {"idempotency_key": "one"})
        two = b.call("presence/open", {"idempotency_key": "two"})
        self.assertEqual(a.call("presence/view", {"account_id": ga["id"]})["active_sessions"], 2)
        a.call("presence/close", {"session_id": one["session_id"], "sequence": 2})
        a.call("presence/refresh", {"session_id": one["session_id"], "sequence": 3}, expected=409)
        self.assertEqual(a.call("presence/view", {"account_id": ga["id"]})["state"], "online")
        b.call("presence/close", {"session_id": two["session_id"], "sequence": 1})
        self.assertEqual(a.call("presence/view", {"account_id": ga["id"]})["state"], "offline")

    def test_05_presence_privacy_and_unknown(self):
        a, ga, *_ = self.env.identity()
        b, _, *_ = self.env.identity()
        self.assertEqual(a.call("presence/view", {"account_id": ga["id"]})["state"], "unknown")
        b.call("presence/view", {"account_id": ga["id"]}, expected=403)

    def test_06_invite_cross_region_owner_and_receipts(self):
        a, ga, b, gb = self.friends()
        allocation, _ = self.env.reserve(a, self.west_grant["id"])
        self.west.call("placement/confirm", {"reservation_id": allocation["reservation_id"], "ticket": allocation["ticket"]})
        event = {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "invite",
                 "room_id": allocation["room_id"], "room_epoch": allocation["room_epoch"]}
        accepted = a.call("social/apply", event)
        self.assertEqual(a.call("social/apply", event)["cursor"], accepted["cursor"])
        changed = dict(event, room_epoch=999)
        a.call("social/apply", changed, expected=409)
        inbox = b.call("social/inbox", {"after": accepted["cursor"]-1})
        self.assertFalse(inbox["events"][0]["delivered"])
        a.call("social/ack", {"cursors": [accepted["cursor"]], "state": "delivered"}, expected=403)
        b.call("social/ack", {"cursors": [accepted["cursor"], accepted["cursor"]], "state": "delivered"})
        receipt = b.call("social/inbox", {"after": accepted["cursor"]-1})["events"][0]
        self.assertTrue(receipt["delivered"])
        self.assertFalse(receipt["seen"])
        b.call("social/ack", {"cursor": accepted["cursor"], "state": "seen"})
        seen = b.call("social/inbox", {"after": accepted["cursor"]-1})["events"][0]
        self.assertTrue(seen["delivered"] and seen["seen"])
        self.assertEqual(a.call("social/state", {})["deliveries"][0]["state"], "seen")
        owner = b.call("room/locate", {"room_id": allocation["room_id"]})
        self.assertEqual(owner["node_id"], self.west_grant["id"])
        joined = b.call("placement/reserve", {"idempotency_key": secrets.token_hex(8), "intent": "join",
            "room_id": allocation["room_id"], "slots": 1, "bandwidth": 1000})
        self.assertEqual(joined["node_id"], self.west_grant["id"])
        self.east.call("placement/confirm", {"reservation_id": joined["reservation_id"], "ticket": joined["ticket"]}, expected=403)
        self.west.call("placement/confirm", {"reservation_id": joined["reservation_id"], "ticket": joined["ticket"]})
        # Real signed admission exercises companion accounting; only the isolated DB clock is adjusted.
        query=lambda statement: subprocess.run(['psql',(self.env.path/'db').read_text(),'-v','ON_ERROR_STOP=1',
            '-At','-c',statement],check=True,capture_output=True,text=True).stdout.strip()
        pair="low_id=LEAST('"+ga['id']+"','"+gb['id']+"') AND high_id=GREATEST('"+ga['id']+"','"+gb['id']+"')"
        self.assertEqual(query('SELECT seconds FROM companion_activity WHERE '+pair),'0')
        query('UPDATE companion_activity SET last_seen=last_seen-10 WHERE '+pair)
        self.west.call("placement/confirm", {"reservation_id": joined["reservation_id"], "ticket": joined["ticket"]})
        seconds=int(query('SELECT seconds FROM companion_activity WHERE '+pair))
        self.assertTrue(10<=seconds<=12)
        self.west.call("placement/release", {"reservation_id": joined["reservation_id"]})
        self.assertEqual(query('SELECT lease_until FROM companion_activity WHERE '+pair),'0')
        query('UPDATE companion_activity SET last_seen=last_seen-10 WHERE '+pair)
        self.west.call("placement/confirm", {"reservation_id": allocation["reservation_id"], "ticket": allocation["ticket"]})
        self.assertEqual(int(query('SELECT seconds FROM companion_activity WHERE '+pair)),seconds)
        self.west.call("placement/release", {"reservation_id": joined["reservation_id"]})
        self.west.call("placement/release", {"reservation_id": allocation["reservation_id"]})

    def test_07_reservation_idempotence_and_auth(self):
        a, _, *_ = self.env.identity()
        b, _, *_ = self.env.identity()
        allocation, body = self.env.reserve(a, self.west_grant["id"])
        self.assertEqual(a.call("placement/reserve", body)["reservation_id"], allocation["reservation_id"])
        a.call("placement/reserve", dict(body, slots=2), expected=409)
        b.call("placement/release", {"reservation_id": allocation["reservation_id"]}, expected=403)
        a.call("placement/confirm", {"reservation_id": allocation["reservation_id"], "ticket": allocation["ticket"]}, expected=403)
        a.call("placement/release", {"reservation_id": allocation["reservation_id"]})

    def test_08_one_slot_hundred_racers(self):
        node, node_grant, *_ = self.env.node(slots=1)
        players = [self.env.identity()[0] for _ in range(100)]
        replica = self.env.replica()
        for player in players[50:]:
            player.base = replica.base
        requests = []
        for player in players:
            candidates = player.call("placement/candidates", {"region": "cn-south", "operator": "test"})
            requests.append({"idempotency_key": secrets.token_hex(8), "room_id": secrets.token_hex(12), "intent": "new",
                "probe_token": candidates["probe_token"], "measurements": [{"node_id": node_grant["id"], "rtt_ms": 5}], "slots": 1, "bandwidth": 1000})
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
            results = list(pool.map(lambda pair: pair[0].call("placement/reserve", pair[1], expected=None), zip(players, requests)))
        self.assertEqual(sum(status == 200 for status, _ in results), 1, results)
        self.assertTrue(all(status in (200, 409) for status, _ in results), results)
        winning = next(body for status, body in results if status == 200)
        node.call("placement/release", {"reservation_id": winning["reservation_id"]})
        self.env.admin.call("admin/node", {"id": node_grant["id"], "status": "draining"})

    def test_09_restart_durable_outbox(self):
        a, ga, b, gb = self.friends()
        allocation, _ = self.env.reserve(a, self.west_grant["id"])
        event = {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "invite",
                 "room_id": allocation["room_id"], "room_epoch": allocation["room_epoch"]}
        accepted = a.call("social/apply", event)
        self.env.restart()
        inbox = b.call("social/inbox", {"after": accepted["cursor"]-1})
        self.assertEqual(inbox["events"][0]["event_id"], event["event_id"])
        self.assertEqual(b.call("room/locate", {"room_id": allocation["room_id"]})["node_id"], self.west_grant["id"])
        a.call("placement/release", {"reservation_id": allocation["reservation_id"]})

    def test_10_credential_revoke_preserves_node_identity(self):
        credential = secrets.token_hex(32)
        self.env.admin.call("admin/credential", {"id": "revoke-test", "credential": credential, "pool": "community"})
        client, grant, key, payload, _ = self.env.node(credential=credential)
        self.env.admin.call("admin/credential/revoke", {"id": "revoke-test"})
        self.env.public.call("enrollment/challenge", payload, expected=401)
        client.call("node/renew")
        payload.pop("credential")
        payload["node_id"] = grant["id"]
        challenge = self.env.public.call("enrollment/challenge", payload)
        result = self.env.public.call("enrollment/prove", {"challenge_id": challenge["challenge_id"],
            "signature": key.sign(challenge["message"].encode()).hex()})
        self.assertEqual(result["id"], grant["id"])
        self.env.admin.call("admin/node", {"id": grant["id"], "status": "revoked"})
        Client(self.env.base, self.env.path/"tls.pem", result["token"]).call("node/renew", expected=401)

    def test_11_device_revoke(self):
        client, grant, _, _ = self.env.identity()
        self.env.admin.call("admin/device/revoke", {"account_id": grant["id"], "device_id": "desktop"})
        client.call("presence/open", {"idempotency_key": "no"}, expected=401)

    def test_12_legacy_identity_preserves_account(self):
        issuer = ed25519.Ed25519PrivateKey.generate()
        user = ec.generate_private_key(ec.SECP256R1())
        numbers = user.public_key().public_numbers()
        encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
        ssh_key = issuer.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()+'\n'
        cert = {"uid": secrets.token_hex(16), "home": hashlib.sha256(ssh_key.strip().encode()).hexdigest()[:32],
                "home_key": ssh_key, "username": "legacy_"+secrets.token_hex(6), "created": 1700000000.0,
                "public_key": {"kty": "EC", "crv": "P-256", "x": encode(numbers.x.to_bytes(32, "big")), "y": encode(numbers.y.to_bytes(32, "big"))}}
        field = lambda raw: struct.pack(">I", len(raw))+raw
        signature = field(b"ssh-ed25519")+field(issuer.sign(json.dumps(cert, sort_keys=True, separators=(",", ":")).encode()))
        challenge = self.env.public.call("identity/challenge", {"certificate": cert, "issuer_signature": encode(signature), "device_id": "legacy"})
        r, s = utils.decode_dss_signature(user.sign(challenge["message"].encode(), ec.ECDSA(hashes.SHA256())))
        grant = self.env.public.call("identity/prove", {"challenge_id": challenge["challenge_id"], "signature": encode(r.to_bytes(32,"big")+s.to_bytes(32,"big"))})
        self.assertEqual(grant["id"], cert["uid"]+"."+cert["home"])
        client = Client(self.env.base, self.env.path/"tls.pem", grant["token"])
        self.assertEqual(client.call("identity/lookup", {"identifier": cert["username"].upper()})["accounts"][0]["account_id"], grant["id"])
        forged = dict(cert, username="forged")
        self.env.public.call("identity/challenge", {"certificate": forged, "issuer_signature": encode(signature), "device_id": "bad"}, expected=401)

        # Browser device approval belongs to the control host. A valid user
        # signature alone must not bypass its revocation and idle lease.
        device = ec.generate_private_key(ec.SECP256R1())
        numbers = device.public_key().public_numbers()
        delegated = {"kty":"EC", "crv":"P-256", "x":encode(numbers.x.to_bytes(32,"big")),
                     "y":encode(numbers.y.to_bytes(32,"big"))}
        now = int(time.time())
        delegation = {"a":grant["id"], "p":"buggcraft-launcher-device-v1", "r":"desktop-delegated",
                      "b":now, "e":now+3600, "d":delegated}
        def sign(key, message):
            r,s = utils.decode_dss_signature(key.sign(message.encode(),ec.ECDSA(hashes.SHA256())))
            return encode(r.to_bytes(32,"big")+s.to_bytes(32,"big"))
        request = {"certificate":cert,"issuer_signature":encode(signature),"device_id":delegation["r"],
                   "device_grant":delegation,"delegation_signature":sign(user,json.dumps(delegation,sort_keys=True,separators=(",",":")))}
        self.env.public.call("identity/challenge",request,expected=401)
        self.env.admin.call("admin/device/authorize",dict(request,expires_at=now+600))
        challenge = self.env.public.call("identity/challenge",request)
        delegated_grant = self.env.public.call("identity/prove",{"challenge_id":challenge["challenge_id"],
                              "signature":sign(device,challenge["message"])})
        self.assertEqual(delegated_grant["id"],grant["id"])
        self.assertLessEqual(delegated_grant["expires_at"],now+600)
        delegated_client = Client(self.env.base,self.env.path/"tls.pem",delegated_grant["token"])
        self.assertLessEqual(delegated_client.call("identity/renew")["expires_at"],now+600)
        self.env.admin.call("admin/device/revoke",{"account_id":grant["id"],"device_id":delegation["r"]})
        delegated_client.call("identity/renew",expected=401)
        self.env.public.call("identity/challenge",request,expected=401)
        self.env.admin.call("admin/device/authorize",dict(request,expires_at=now+600),expected=403)

    def test_13_invite_revoke_blocks_join(self):
        a, ga, b, gb = self.friends()
        allocation, _ = self.env.reserve(a, self.west_grant["id"])
        event = {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "invite",
                 "room_id": allocation["room_id"], "room_epoch": allocation["room_epoch"]}
        a.call("social/apply", event)
        a.call("social/apply", dict(event, kind="invite_revoke", event_id=secrets.token_hex(8), invite_event_id=event["event_id"]))
        b.call("room/locate", {"room_id": allocation["room_id"]}, expected=403)
        a.call("placement/release", {"reservation_id": allocation["reservation_id"]})

    def test_14_websocket_push_and_replay(self):
        a, ga, *_ = self.env.identity()
        b, gb, *_ = self.env.identity()
        channel = WebSocketClient(b)
        self.addCleanup(channel.close)
        channel.send("social/subscribe", {"after": 0}, "subscribe")
        self.assertEqual(channel.receive()["status"], 200)
        event = a.call("social/apply", {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "friend_request"})
        pushed = channel.receive()
        self.assertEqual(pushed["event"], "social")
        self.assertEqual(pushed["body"]["events"][0]["cursor"], event["cursor"])
        channel.send("social/ack", {"cursor": event["cursor"], "state": "delivered"}, "ack")
        self.assertEqual(channel.receive()["request_id"], "ack")
        channel.close()
        replay = b.call("social/inbox", {"after": event["cursor"]-1})
        self.assertTrue(replay["events"][0]["delivered"])

    def test_15_forged_derived_account_rejected(self):
        victim, grant, *_ = self.env.identity()
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        challenge = self.env.public.call("identity/challenge", {"public_key": public, "device_id": "test", "verified_account_id": grant["id"]})
        result = self.env.public.call("identity/prove", {"challenge_id": challenge["challenge_id"], "signature": key.sign(challenge["message"].encode()).hex()})
        self.assertNotEqual(result["id"], grant["id"])

    def test_16_draining_affects_only_new_allocations(self):
        node, grant, *_ = self.env.node()
        player, *_ = self.env.identity()
        allocated, _ = self.env.reserve(player, grant["id"])
        self.env.admin.call("admin/node", {"id": grant["id"], "status": "draining"})
        candidates = player.call("placement/candidates", {"region": "cn-south", "operator": "test"})
        self.assertNotIn(grant["id"], [item["node_id"] for item in candidates["candidates"]])
        node.call("placement/confirm", {"reservation_id": allocated["reservation_id"], "ticket": allocated["ticket"]})
        node.call("placement/release", {"reservation_id": allocated["reservation_id"]})

    def test_17_node_budget_and_probe_proof(self):
        key = ed25519.Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        payload = {"public_key": public, "credential": self.env.credential, "region": "cn-south", "operator": "test",
                   "endpoint": "127.0.0.1:23456", "slots": 99999, "bandwidth": 1000, "protocol": 1}
        self.env.public.call("enrollment/challenge", payload, expected=409)
        payload["slots"] = 1
        challenge = self.env.public.call("enrollment/challenge", payload)
        grant = self.env.public.call("enrollment/prove", {"challenge_id": challenge["challenge_id"], "signature": key.sign(challenge["message"].encode()).hex()})
        node = Client(self.env.base, self.env.path/"tls.pem", grant["token"])
        node.call("node/activate", {"proof_endpoint": self.env.proofs[0].endpoint}, expected=409)

    def test_18_replica_routes_events_during_primary_exit(self):
        replica = self.env.replica()
        a, ga, *_ = self.env.identity()
        b, gb, *_ = self.env.identity()
        alternate = Client(replica.base, self.env.path/"tls.pem", a.token)
        event = {"event_id": secrets.token_hex(8), "target": gb["id"], "kind": "friend_request"}
        accepted = alternate.call("social/apply", event)
        self.assertEqual(b.call("social/inbox", {"after": accepted["cursor"]-1})["events"][0]["event_id"], event["event_id"])
        self.env.process.terminate()
        self.env.process.wait(timeout=15)
        alternate.call("presence/open", {"idempotency_key": "failover"})
        self.assertEqual(alternate.call("social/apply", event)["cursor"], accepted["cursor"])
        self.env.start()


if __name__ == "__main__":
    unittest.main(verbosity=2)

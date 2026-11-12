"""One-time private data conversion, never a service or distributed runtime.

Run against a stopped legacy identity adapter. The C++ import revalidates account
and device signatures and refuses to overwrite an initialized identity database.
"""
import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def read(path, fallback):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else fallback


def write_new(path, content):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as target:
        target.write(content)


def export(accounts_path, issuer_path, output, blocked):
    records = read(accounts_path, [])
    devices = read(accounts_path.with_name('launcher-devices.json'), {})
    mail_entries = read(accounts_path.with_name('accounts-email.json'), [])
    if not isinstance(records, list) or not isinstance(devices, dict) or not isinstance(mail_entries, list):
        raise ValueError('Invalid legacy identity stores')
    account_ids = {record['state']['account'] for record in records}
    links, choices = set(), {}
    for entry in mail_entries:
        body = entry['body']
        if body['kind'] == 'link':
            links.add((body['mailbox'], body['account']))
        elif body['kind'] == 'choice':
            previous = choices.get(body['mailbox'])
            if previous is None or body['revision'] > previous['revision']:
                choices[body['mailbox']] = body
        else:
            raise ValueError('Unknown mailbox record kind')
    if any(account not in account_ids for _, account in links):
        raise ValueError('Mailbox refers to an account missing from the source snapshot')
    snapshot = dict(version=1, accounts=[dict(record=r, blocked=r['state']['account'] in blocked)
        for r in records], devices=devices,
        mailboxes=[dict(mailbox=m, account=a, preferred=choices.get(m, {}).get('account') == a)
                   for m, a in sorted(links)])
    key_bytes = issuer_path.read_bytes()
    key = (serialization.load_ssh_private_key(key_bytes, password=None) if key_bytes.startswith(b'-----BEGIN OPENSSH')
           else serialization.load_pem_private_key(key_bytes, password=None))
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError('Identity issuer must use Ed25519')
    # No source files or keys are changed. Refuse all output replacement.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_new(output/'snapshot.json', json.dumps(snapshot, ensure_ascii=True, separators=(',', ':')).encode())
    write_new(output/'issuer.pem', key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    write_new(output/'issuer.pub', key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                              serialization.PublicFormat.OpenSSH))
    return dict(accounts=len(records), devices=len(devices), mailboxes=len(links))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--issuer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--blocked', type=Path, help='Private JSON array of blocked full account IDs')
    args = parser.parse_args()
    print(json.dumps(export(args.accounts, args.issuer, args.output,
                            set(read(args.blocked, [])) if args.blocked else set())))


if __name__ == '__main__':
    main()

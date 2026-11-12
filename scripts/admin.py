"""Administrative HTTPS client. Credentials are read from files, never command arguments."""
import argparse
import json
import ssl
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("credential", "credential/revoke", "node", "device/revoke"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    args = parser.parse_args()
    if not args.url.startswith("https://"):
        parser.error("HTTPS is required")
    context = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    token = args.token_file.read_text(encoding="utf-8").strip()
    data = args.body_file.read_bytes()
    json.loads(data)
    request = urllib.request.Request(args.url.rstrip("/")+"/v1/admin/"+args.operation,
        data=data, method="POST", headers={"Authorization": "Bearer "+token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        # Replies contain IDs/status only; the service does not echo enrollment secrets.
        print(json.dumps(json.load(response), ensure_ascii=False))


if __name__ == "__main__":
    main()

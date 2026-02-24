#!/usr/bin/env python3
import hashlib
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("MOCK_OPENBAO_PORT", "18200"))
TOKEN = "mock-client-token"
SERVICE_PATH_PATTERN = re.compile(r"^/v1/secret/data/bootroot/services/([^/]+)/([^/]+)$")
CONTROL_ITEMS = {"secret_id", "eab", "http_responder_hmac", "trust"}
versions: dict[tuple[str, str], int] = {}
fail_next: dict[tuple[str, str], int] = {}


def write_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/auth/approle/login":
            write_json(self, 200, {"auth": {"client_token": TOKEN}})
            return
        if self.path == "/control/set-version":
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            service = str(payload.get("service", "")).strip()
            item = str(payload.get("item", "")).strip()
            version = int(payload.get("version", 1))
            if not service or item not in CONTROL_ITEMS or version < 1:
                write_json(self, 400, {"error": "invalid control payload"})
                return
            versions[(service, item)] = version
            write_json(self, 200, {"ok": True})
            return
        if self.path == "/control/fail-next":
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            service = str(payload.get("service", "")).strip()
            item = str(payload.get("item", "")).strip()
            count = int(payload.get("count", 1))
            if not service or item not in CONTROL_ITEMS or count < 1:
                write_json(self, 400, {"error": "invalid control payload"})
                return
            fail_next[(service, item)] = count
            write_json(self, 200, {"ok": True})
            return
        if self.path == "/control/reset":
            versions.clear()
            fail_next.clear()
            write_json(self, 200, {"ok": True})
            return
        write_json(self, 404, {"errors": ["not found"]})

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/sys/health":
            write_json(self, 200, {"initialized": True, "sealed": False})
            return
        match = SERVICE_PATH_PATTERN.match(self.path)
        if match:
            service = match.group(1)
            secret_kind = match.group(2)
            failure_key = (service, secret_kind)
            if fail_next.get(failure_key, 0) > 0:
                fail_next[failure_key] = fail_next[failure_key] - 1
                write_json(self, 500, {"errors": [f"injected failure for {service}/{secret_kind}"]})
                return
            version = versions.get((service, secret_kind), 1)
            if secret_kind == "secret_id":
                write_json(
                    self,
                    200,
                    {"data": {"data": {"secret_id": f"synced-secret-id-{service}-v{version}"}}},
                )
                return
            if secret_kind == "eab":
                write_json(
                    self,
                    200,
                    {
                        "data": {
                            "data": {
                                "kid": f"synced-kid-{service}-v{version}",
                                "hmac": f"synced-hmac-{service}-v{version}",
                            }
                        }
                    },
                )
                return
            if secret_kind == "http_responder_hmac":
                write_json(
                    self,
                    200,
                    {"data": {"data": {"hmac": f"synced-responder-hmac-{service}-v{version}"}}},
                )
                return
            if secret_kind == "trust":
                fingerprint = hashlib.sha256(f"{service}-v{version}".encode()).hexdigest()
                write_json(
                    self,
                    200,
                    {
                        "data": {
                            "data": {
                                "trusted_ca_sha256": [fingerprint],
                                "ca_bundle_pem": (
                                    "-----BEGIN CERTIFICATE-----\n"
                                    f"SMOKE-{service}-v{version}\n"
                                    "-----END CERTIFICATE-----"
                                ),
                            }
                        }
                    },
                )
                return
        write_json(self, 404, {"errors": ["not found"]})


def main() -> None:
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import os
import re
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer


PORT = int(os.environ.get("MOCK_OPENBAO_PORT", "18200"))
TOKEN = "mock-client-token"
SERVICE_PATH_PATTERN = re.compile(r"^/v1/secret/data/bootroot/services/([^/]+)/([^/]+)$")


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
        write_json(self, 404, {"errors": ["not found"]})

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/v1/sys/health":
            write_json(self, 200, {"initialized": True, "sealed": False})
            return
        match = SERVICE_PATH_PATTERN.match(self.path)
        if match:
            service = match.group(1)
            secret_kind = match.group(2)
            if secret_kind == "secret_id":
                write_json(
                    self,
                    200,
                    {"data": {"data": {"secret_id": f"synced-secret-id-{service}"}}},
                )
                return
            if secret_kind == "eab":
                write_json(
                    self,
                    200,
                    {
                        "data": {
                            "data": {
                                "kid": f"synced-kid-{service}",
                                "hmac": f"synced-hmac-{service}",
                            }
                        }
                    },
                )
                return
            if secret_kind == "http_responder_hmac":
                write_json(
                    self,
                    200,
                    {"data": {"data": {"hmac": f"synced-responder-hmac-{service}"}}},
                )
                return
            if secret_kind == "trust":
                fingerprint = hashlib.sha256(service.encode("utf-8")).hexdigest()
                write_json(
                    self,
                    200,
                    {
                        "data": {
                            "data": {
                                "trusted_ca_sha256": [fingerprint],
                                "ca_bundle_pem": (
                                    "-----BEGIN CERTIFICATE-----\n"
                                    f"SMOKE-{service}\n"
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

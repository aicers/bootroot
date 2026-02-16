#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


PORT = int(os.environ.get("MOCK_OPENBAO_PORT", "18200"))
SERVICE = os.environ.get("SERVICE_NAME", "edge-proxy")
TOKEN = "mock-client-token"


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
        base = f"/v1/secret/data/bootroot/services/{SERVICE}"
        if self.path == "/v1/sys/health":
            write_json(self, 200, {"initialized": True, "sealed": False})
            return
        if self.path == f"{base}/secret_id":
            write_json(self, 200, {"data": {"data": {"secret_id": "synced-secret-id"}}})
            return
        if self.path == f"{base}/eab":
            write_json(
                self,
                200,
                {"data": {"data": {"kid": "synced-kid", "hmac": "synced-hmac"}}},
            )
            return
        if self.path == f"{base}/http_responder_hmac":
            write_json(
                self,
                200,
                {"data": {"data": {"hmac": "synced-responder-hmac"}}},
            )
            return
        if self.path == f"{base}/trust":
            write_json(
                self,
                200,
                {
                    "data": {
                        "data": {
                            "trusted_ca_sha256": ["33" * 32],
                            "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nSMOKE\n-----END CERTIFICATE-----",
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

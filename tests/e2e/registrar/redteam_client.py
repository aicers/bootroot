#!/usr/bin/env python3
"""Minimal external caller for the registrar red-team scenario.

This intentionally uses only the documented socket envelope and standard
library TLS.  It is not a second implementation of bootroot's registrar
client: the scenario needs a process boundary that can be run as a selected
uid, and it checks the two trust inputs (endpoint name and anchor pin) before
letting Python's TLS implementation authenticate the server.
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import ssl
import struct
import sys
from pathlib import Path


def pin_set(path: Path) -> set[str]:
    values: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            values.add(value)
    if not values:
        raise ValueError("endpoint pin file has no fingerprints")
    return values


def assert_anchor_is_pinned(ca_path: Path, pins_path: Path) -> None:
    der = ssl.PEM_cert_to_DER_cert(ca_path.read_text(encoding="utf-8"))
    fingerprint = hashlib.sha256(der).hexdigest()
    if fingerprint not in pin_set(pins_path):
        raise ValueError("endpoint anchor fingerprint is not present in the pin file")


def exchange(args: argparse.Namespace) -> bytes:
    assert_anchor_is_pinned(args.ca, args.pins)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(args.ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
    payload = args.payload.read_bytes()
    name = args.operation.encode("ascii")
    if not name or len(name) > 32:
        raise ValueError("operation must contain 1 through 32 ASCII bytes")
    frame = len(payload).to_bytes(4, "big") + bytes([len(name)]) + name + payload
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
        raw.settimeout(15)
        raw.connect(str(args.socket))
        # The red-team scenario runs the endpoint under root.  Metadata at
        # the pathname is not proof of who accepted this connection: the
        # live peer credential is.  Refuse before a TLS byte is sent when a
        # post-bind ownership transition left an unprivileged listener alive.
        if hasattr(socket, "SO_PEERCRED"):
            _pid, uid, _gid = struct.unpack(
                "3i", raw.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if uid != 0:
                raise ValueError(f"registrar endpoint peer uid is {uid}, expected root")
        with context.wrap_socket(raw, server_hostname=args.endpoint_name) as stream:
            stream.sendall(frame)
            response = bytearray()
            while True:
                chunk = stream.recv(65540)
                if not chunk:
                    break
                response.extend(chunk)
    return bytes(response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--endpoint-name", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--expect-empty", action="store_true")
    args = parser.parse_args()
    try:
        response = exchange(args)
        if args.expect_empty:
            if response:
                raise ValueError("endpoint returned application bytes for a refused operation")
            return 0
        if len(response) < 4:
            raise ValueError("endpoint closed without a complete response frame")
        declared = int.from_bytes(response[:4], "big")
        body = response[4:]
        if declared != len(body):
            raise ValueError("endpoint response length does not match its frame prefix")
        print(body.decode("utf-8"))
        return 0
    except Exception as error:  # a scenario failure needs a compact diagnostic
        print(f"registrar red-team client: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

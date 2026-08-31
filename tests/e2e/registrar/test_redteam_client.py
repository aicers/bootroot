"""Focused non-Docker checks for the registrar red-team client."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

CLIENT_PATH = Path(__file__).with_name("redteam_client.py")
SPEC = importlib.util.spec_from_file_location("redteam_client", CLIENT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
redteam_client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(redteam_client)


class RedteamClientTests(unittest.TestCase):
    """The client-side assertion for a refused unknown operation."""

    def test_accepts_only_the_framed_unknown_operation_marker(self) -> None:
        marker = (
            len(redteam_client.UNKNOWN_OPERATION_REFUSAL).to_bytes(4, "big")
            + redteam_client.UNKNOWN_OPERATION_REFUSAL
        )

        self.assertIsNone(redteam_client.assert_response(marker, True))

    def test_rejects_an_unrelated_empty_exchange(self) -> None:
        with self.assertRaisesRegex(ValueError, "did not identify"):
            redteam_client.assert_response(b"", True)

    def test_rejects_a_wrong_framed_marker(self) -> None:
        wrong = len(b"different-refusal").to_bytes(4, "big") + b"different-refusal"

        with self.assertRaisesRegex(ValueError, "did not identify"):
            redteam_client.assert_response(wrong, True)


if __name__ == "__main__":
    unittest.main()

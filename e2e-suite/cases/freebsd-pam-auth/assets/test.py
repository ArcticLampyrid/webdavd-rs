#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""Check the same service-owned file with each set of credentials."""

import httpx2

URL = "http://127.0.0.1:8080/private/probe.txt"


def main():
    with httpx2.Client(timeout=60) as dav:
        for credentials, status in [
            (("alice", "alice-e2e-pw"), 200),  # exactly min-uid
            (("alice", "wrong-password"), 401),
            (("lowuid", "lowuid-e2e-pw"), 403),  # PAM succeeds; min-uid rejects
            (("lowuid", "wrong-password"), 401),
            (("expired", "expired-e2e-pw"), 401),
            (("unknown", "wrong-password"), 401),
            (None, 401),
        ]:
            response = dav.get(URL, auth=credentials)
            user = credentials[0] if credentials else "anonymous"
            assert response.status_code == status, (
                f"GET {URL} as {user}: status {response.status_code}, expected {status}"
            )
            if status == 200:
                assert response.content == b"service account only\n"
    print("FreeBSD PAM authentication: ok")


if __name__ == "__main__":
    main()

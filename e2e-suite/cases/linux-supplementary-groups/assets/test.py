#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""Supplementary groups: alice is in sharedgrp, bob is not. Only members of
sharedgrp can read and write the root:sharedgrp directory with mode 0770.

The accounts and the directory must agree with config.yaml.
"""

import httpx2

BASE_URL = "http://127.0.0.1:8080"
ROOT = "/groups/secret"
FILE = f"{ROOT}/alice.txt"


class Dav(httpx2.Client):
    """webdavd client that names the account and the path in a failed check."""

    def __init__(self, user=None, password=None):
        self.user = user or "anonymous"
        super().__init__(base_url=BASE_URL, auth=(user, password) if user else None, timeout=60)

    def expect(self, status, method, path, **kwargs):
        """Send one request. Fail unless the response has `status`. Return the response."""
        response = self.request(method, path, **kwargs)
        assert response.status_code == status, (
            f"{method} {path} as {self.user}: status {response.status_code}, expected {status}"
        )
        return response


def main():
    with Dav("alice", "alice-e2e-pw") as alice, Dav("bob", "bob-e2e-pw") as bob:
        alice.expect(201, "PUT", FILE, content=b"for sharedgrp")
        content = alice.expect(200, "GET", FILE).content
        assert content == b"for sharedgrp", f"{FILE}: unexpected content {content!r}"

        bob.expect(403, "GET", FILE)
        bob.expect(403, "PUT", f"{ROOT}/bob.txt", content=b"intrusion")

        alice.expect(204, "DELETE", FILE)
    print("supplementary groups: ok")


if __name__ == "__main__":
    main()

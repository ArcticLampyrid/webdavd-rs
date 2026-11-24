#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""PAM authentication: the accounts alice and bob get access, while a wrong
password, an unknown account, and an anonymous request get 401 Unauthorized.

The accounts must agree with config.yaml.
"""

import httpx2

BASE_URL = "http://127.0.0.1:8080"
ROOT = "/groups"


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
    propfind = {"Depth": "0", "Content-Type": "application/xml"}
    for user, password, status in [
        ("alice", "alice-e2e-pw", 207),
        ("bob", "bob-e2e-pw", 207),
        ("alice", "wrong-password", 401),
        ("mallory", "mallory-e2e-pw", 401),
        (None, None, 401),
    ]:
        with Dav(user, password) as dav:
            dav.expect(status, "PROPFIND", ROOT, content=b"", headers=propfind)
    print("PAM authentication: ok")


if __name__ == "__main__":
    main()

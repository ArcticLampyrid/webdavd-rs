#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""PAM login, minimum UID, and POSIX ACLs in the guest filesystem.

The accounts must agree with config.yaml.
"""

import pwd
from pathlib import Path

import httpx2

BASE_URL = "http://127.0.0.1:8080"
ROOT = "/groups"
SHARED = f"{ROOT}/shared"
DISK = Path("/srv/webdav/groups/shared")


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


def check_login():
    # This collection is traversable by everyone: a 403 here is not an ACL denial.
    propfind = {"Depth": "0", "Content-Type": "application/xml"}
    for user, password, status in [
        ("alice", "alice-e2e-pw", 207),
        ("bob", "bob-e2e-pw", 207),
        ("carol", "carol-e2e-pw", 207),
        ("lowuid", "lowuid-e2e-pw", 403),
        ("lowuid", "wrong-password", 401),
        ("alice", "wrong-password", 401),
        ("mallory", "mallory-e2e-pw", 401),
        (None, None, 401),
    ]:
        with Dav(user, password) as dav:
            dav.expect(status, "PROPFIND", ROOT, content=b"", headers=propfind)
    print("PAM authentication: ok")


def check_writer():
    with Dav("alice", "alice-e2e-pw") as alice:
        alice.expect(201, "PUT", f"{SHARED}/alice.txt", content=b"written by alice")
    owner = (DISK / "alice.txt").stat()
    alice = pwd.getpwnam("alice")
    assert (owner.st_uid, owner.st_gid) == (alice.pw_uid, alice.pw_gid), (
        f"alice.txt: unexpected owner {owner.st_uid}:{owner.st_gid}"
    )
    print("supplementary group write and file ownership: ok")


def check_reader_and_outsider():
    with Dav("bob", "bob-e2e-pw") as bob, Dav("carol", "carol-e2e-pw") as carol:
        assert bob.expect(200, "GET", f"{SHARED}/seed.txt").content == b"shared\n"
        bob.expect(403, "PUT", f"{SHARED}/bob.txt", content=b"denied")
        carol.expect(403, "GET", f"{SHARED}/seed.txt")
        carol.expect(403, "PUT", f"{SHARED}/carol.txt", content=b"denied")
    assert not (DISK / "bob.txt").exists()
    assert not (DISK / "carol.txt").exists()
    print("named user and outsider ACL restrictions: ok")


if __name__ == "__main__":
    check_login()
    check_writer()
    check_reader_and_outsider()

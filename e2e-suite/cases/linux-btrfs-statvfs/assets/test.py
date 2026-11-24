#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""Btrfs statvfs: Btrfs has no quotactl user quota, so both users get the
filesystem space (a 256 MiB disk).

The accounts and the disk size must agree with config.yaml.
"""

import os
import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

import httpx2

BASE_URL = "http://127.0.0.1:8080"
MIB = 1 << 20
DISK_SIZE = 256 * MIB
HARD_LIMIT = 8 * MIB
ROOT = "/btrfs"
QUOTA_PROPFIND = b"""<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop><D:quota-available-bytes/><D:quota-used-bytes/></D:prop>
</D:propfind>"""
QUOTA_HEADERS = {"Depth": "0", "Content-Type": "application/xml"}


class Quota(NamedTuple):
    """RFC 4331 quota properties of a collection."""

    used: int
    available: int

    @property
    def total(self):
        """Bytes used plus bytes available: the effective limit."""
        return self.used + self.available


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

    def quota(self, path):
        """Quota properties of `path`."""
        response = self.expect(207, "PROPFIND", path, content=QUOTA_PROPFIND, headers=QUOTA_HEADERS)
        values = {
            element.tag.rpartition("}")[2]: element.text
            for element in ElementTree.fromstring(response.content).iter()
        }
        try:
            return Quota(int(values["quota-used-bytes"]), int(values["quota-available-bytes"]))
        except (KeyError, TypeError, ValueError) as error:
            raise AssertionError(f"{path}: no quota in {response.content!r}") from error


def main():
    with Dav("alice", "alice-e2e-pw") as alice:
        file = f"{ROOT}/alice.bin"
        data = os.urandom(MIB)
        alice.expect(201, "PUT", file, content=data)
        content = alice.expect(200, "GET", file).content
        assert content == data, f"{file}: unexpected content"

        for user, password in [("alice", "alice-e2e-pw"), ("bob", "bob-e2e-pw")]:
            with Dav(user, password) as dav:
                quota = dav.quota(ROOT)
                assert quota.available > HARD_LIMIT and quota.total <= DISK_SIZE, (
                    f"{ROOT}: {user} has {quota}, expected filesystem space"
                )

        alice.expect(204, "DELETE", file)
    print("btrfs statvfs: ok")


if __name__ == "__main__":
    main()

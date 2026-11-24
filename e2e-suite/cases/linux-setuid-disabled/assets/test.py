#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""setuid disabled: without uid switching, the quota lookup has no user and
uses statvfs, so it reports the tmpfs space.

The account and the tmpfs size must agree with config.yaml.
"""

import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

import httpx2

BASE_URL = "http://127.0.0.1:8080"
MIB = 1 << 20
TMPFS_SIZE = 16 * MIB
ROOT = "/nosetuid"
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
    with Dav("alice", "alice-e2e-pw") as dav:
        quota = dav.quota(ROOT)
        assert quota.total == TMPFS_SIZE and quota.available > 0, (
            f"{ROOT}: {quota}, expected tmpfs space {TMPFS_SIZE}"
        )
    print("setuid disabled: ok")


if __name__ == "__main__":
    main()

#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""XFS user quota: alice sees her soft limit, and the kernel stops her at the
hard limit. bob has no limit: he sees the filesystem space.

The accounts and limits must agree with config.yaml.
"""

import itertools
import os
import time
import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

import httpx2

BASE_URL = "http://127.0.0.1:8080"
MIB = 1 << 20
SOFT_LIMIT = 4 * MIB
HARD_LIMIT = 8 * MIB
ROOT = "/xfs"

# Size of each file that fill() writes. When the quota is reached, webdavd
# answers before it reads the request body, then closes the connection. A
# small body is sent completely before that, so the client reads the answer.
FILL_CHUNK = 64 * 1024
# webdavd caches quota lookups for 30 s. quota_until() waits longer than that.
QUOTA_WAIT = 45
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

    def quota_until(self, path, condition):
        """Quota of `path`, once it satisfies `condition`. A quota change becomes
        visible after the filesystem accounts for it, and the webdavd cache expires."""
        deadline = time.monotonic() + QUOTA_WAIT
        while not condition(quota := self.quota(path)):
            assert time.monotonic() < deadline, f"{path}: quota {quota} did not change in {QUOTA_WAIT} s"
            time.sleep(2)
        return quota

    def fill(self, directory, limit):
        """Write files into `directory` until webdavd answers 507 Insufficient
        Storage. Return the number of bytes written before that."""
        written = 0
        for index in itertools.count():
            path = f"{directory}/fill-{index}.bin"
            status = self.put(path, content=os.urandom(FILL_CHUNK)).status_code
            if status == 507:
                return written
            assert status == 201, f"PUT {path} as {self.user}: status {status}, expected 201"
            written += FILL_CHUNK
            assert written <= limit, f"{directory}: wrote {written} bytes without 507 Insufficient Storage"


def main():
    with Dav("alice", "alice-e2e-pw") as alice, Dav("bob", "bob-e2e-pw") as bob:
        directory = f"{ROOT}/alice-quota"
        alice.expect(201, "MKCOL", directory)
        alice.expect(201, "PUT", f"{directory}/2mib.bin", content=os.urandom(2 * MIB))

        quota = alice.quota_until(ROOT, lambda quota: quota.used >= 2 * MIB)
        assert quota.total == SOFT_LIMIT, f"{ROOT}: alice has {quota}, expected soft limit {SOFT_LIMIT}"

        stored = quota.used + alice.fill(directory, HARD_LIMIT)
        assert SOFT_LIMIT < stored <= HARD_LIMIT, (
            f"{ROOT}: alice stored {stored} bytes, expected between soft and hard limit"
        )

        unlimited = bob.quota(ROOT)
        assert unlimited.available > HARD_LIMIT, f"{ROOT}: bob has {unlimited}, expected filesystem space"

        alice.expect(204, "DELETE", directory)
    print("xfs user quota: ok")


if __name__ == "__main__":
    main()

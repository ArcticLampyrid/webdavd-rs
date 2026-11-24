#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""ZFS dataset quota: statvfs of a ZFS dataset reports the dataset quota, and
ZFS stops writes at approximately the quota.

Per-request uid switching is Linux-only. Thus webdavd runs as alice without
authentication. The dataset and its quota must agree with config.yaml.
"""

import itertools
import os
import time
import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

import httpx2

BASE_URL = "http://127.0.0.1:8080"
MIB = 1 << 20
ZFS_QUOTA = 10 * MIB
ROOT = "/zfs"

# Size of each file that fill() writes. When the disk is full, webdavd answers
# before it reads the request body, then closes the connection. A small body
# is sent completely before that, so the client reads the answer.
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

    def __init__(self):
        self.user = "anonymous"
        super().__init__(base_url=BASE_URL, timeout=60)

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
    with Dav() as dav:
        before = dav.quota(ROOT)
        assert ZFS_QUOTA - MIB < before.total <= ZFS_QUOTA, (
            f"{ROOT}: {before}, expected dataset quota {ZFS_QUOTA}"
        )

        directory = f"{ROOT}/fill"
        dav.expect(201, "MKCOL", directory)
        dav.expect(201, "PUT", f"{directory}/2mib.bin", content=os.urandom(2 * MIB))
        # ZFS accounts for writes when it commits the transaction group.
        dav.quota_until(ROOT, lambda quota: quota.available + MIB < before.available)

        # ZFS compares the quota with an estimate of the pending writes, so the
        # last write can go a little over the quota.
        stored = 2 * MIB + dav.fill(directory, 2 * ZFS_QUOTA)
        assert ZFS_QUOTA // 2 < stored <= ZFS_QUOTA + 2 * MIB, (
            f"{ROOT}: stored {stored} bytes, expected approximately the dataset quota {ZFS_QUOTA}"
        )

        dav.expect(204, "DELETE", directory)
    print("zfs dataset quota: ok")


if __name__ == "__main__":
    main()

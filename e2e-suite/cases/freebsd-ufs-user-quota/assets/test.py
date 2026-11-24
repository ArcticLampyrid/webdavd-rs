#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx2"]
# ///
"""UFS user quota: without uid switching, /ufs reports the filesystem space
(a 128 MiB disk), but the kernel enforces the user quota of the server account
alice. The kernel stops all writes at her hard limit.

The account and limits must agree with config.yaml.
"""

import itertools
import os
import xml.etree.ElementTree as ElementTree
from typing import NamedTuple

import httpx2

BASE_URL = "http://127.0.0.1:8080"
MIB = 1 << 20
UFS_SOFT_LIMIT = 4 * MIB
UFS_HARD_LIMIT = 8 * MIB
DISK_SIZE = 128 * MIB
ROOT = "/ufs"

# Size of each file that fill() writes. When the quota is reached, webdavd
# answers before it reads the request body, then closes the connection. A
# small body is sent completely before that, so the client reads the answer.
FILL_CHUNK = 64 * 1024
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
        quota = dav.quota(ROOT)
        assert quota.available > UFS_HARD_LIMIT and quota.total <= DISK_SIZE, (
            f"{ROOT}: {quota}, expected filesystem space"
        )

        directory = f"{ROOT}/fill"
        dav.expect(201, "MKCOL", directory)
        stored = dav.fill(directory, UFS_HARD_LIMIT)
        assert UFS_SOFT_LIMIT < stored <= UFS_HARD_LIMIT, (
            f"{ROOT}: stored {stored} bytes, expected between soft and hard limit"
        )

        dav.expect(204, "DELETE", directory)
    print("ufs user quota: ok")


if __name__ == "__main__":
    main()

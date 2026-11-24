# Container image that boots one guest VM for the webdavd E2E tests.
#
# e2e-harness builds one image for each VM profile in e2e-suite/vm-profiles,
# with IMAGE_URL set to the image.url of the profile. The tag is a digest of
# IMAGE_URL and of all files in this directory. The harness binary contains
# these files (see e2e-harness/src/image.rs).
#
# IMAGE_URL is a qcow2 disk image, optionally compressed with xz (.xz) or
# gzip (.gz). The build needs no privileges. See entrypoint.sh for the
# runtime contract.

FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        genisoimage \
        gzip \
        qemu-system-x86 \
        qemu-utils \
        socat \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# The disk image downloads before entrypoint.sh is copied, so that a change
# to entrypoint.sh does not download it again. curl writes to a file, so that
# a retry continues the download (a retry to a pipe corrupts the data).
ARG IMAGE_URL
RUN set -eu; \
    [ -n "${IMAGE_URL:-}" ] || { echo "the build argument IMAGE_URL is necessary" >&2; exit 1; }; \
    case "$IMAGE_URL" in \
        *.xz) suffix=.xz unpack="xz -d" ;; \
        *.gz) suffix=.gz unpack="gzip -d" ;; \
        *) suffix= unpack=true ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --continue-at - --create-dirs \
        -o "/vm/base.qcow2$suffix" "$IMAGE_URL"; \
    $unpack "/vm/base.qcow2$suffix"; \
    chmod 0444 /vm/base.qcow2

# The build context has no executable bits: set them here. Not `COPY --chmod`,
# because the classic Docker builder does not support it.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

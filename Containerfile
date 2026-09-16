# Official Fedora 44 bootc base, pinned to its linux/amd64 manifest.
FROM quay.io/fedora/fedora-bootc@sha256:38ef702a1366d4ae6645dbe77192fe50f91dce487e6c6fffc046f9ad7e9ffa74

ARG SOURCE_REVISION=unknown
ARG BUILD_ID=unknown

LABEL containers.bootc="1" \
      org.opencontainers.image.title="SignalLayerIT CoreOS" \
      org.opencontainers.image.version="0.0.1" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.source="https://github.com/transitionalcomputing/signallayer-coreos"

RUN set -eu; \
    case "${SOURCE_REVISION}${BUILD_ID}" in \
        *[!A-Za-z0-9._+-]*) echo 'Build metadata must use letters, digits, dot, underscore, plus, or hyphen.' >&2; exit 1 ;; \
    esac; \
    install -d -m 0755 /usr/lib/signallayer; \
    printf '%s\n' \
        'NAME="SignalLayerIT CoreOS"' \
        'VERSION="0.0.1"' \
        'PLATFORM_API_VERSION="0.1"' \
        "SOURCE_REVISION=\"${SOURCE_REVISION}\"" \
        "BUILD_ID=\"${BUILD_ID}\"" \
        > /usr/lib/signallayer/release

# Native Rust tooling is confined to build stages, using the same pinned Fedora base.
FROM quay.io/fedora/fedora-bootc@sha256:38ef702a1366d4ae6645dbe77192fe50f91dce487e6c6fffc046f9ad7e9ffa74 AS platform-tools
RUN dnf -y install --setopt=install_weak_deps=False cargo gcc rustfmt && dnf clean all
WORKDIR /build
ENV CARGO_HOME=/build/target/cargo-home

FROM platform-tools AS platform-build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY platformd ./platformd
COPY corectl ./corectl
RUN cargo fmt --all -- --check && cargo test --workspace --locked && cargo build --workspace --release --locked

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

COPY --from=platform-build /build/target/release/sl-platformd /usr/bin/sl-platformd
COPY --from=platform-build /build/target/release/corectl /usr/bin/corectl
COPY image/platform/sl-platformd.service /usr/lib/systemd/system/sl-platformd.service
COPY image/platform/org.signallayer.Platform1.conf /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf
RUN install -d /usr/lib/systemd/system/multi-user.target.wants && \
    ln -s ../sl-platformd.service /usr/lib/systemd/system/multi-user.target.wants/sl-platformd.service

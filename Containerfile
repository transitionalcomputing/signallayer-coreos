# Native Rust tooling is confined to build stages, using the same pinned Fedora base.
FROM ghcr.io/transitionalcomputing/signallayer-base@sha256:ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c AS platform-tools
RUN dnf -y install --setopt=install_weak_deps=False cargo gcc rustfmt && dnf clean all
WORKDIR /build
ENV CARGO_HOME=/build/target/cargo-home

FROM platform-tools AS platform-build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY platformd ./platformd
COPY corectl ./corectl
COPY sessiond ./sessiond
COPY network-observer ./network-observer
COPY authd ./authd
RUN cargo fmt --all -- --check && cargo test --workspace --locked && cargo build --workspace --release --locked

# Policy authoring/analysis tools never enter the final runtime image.
FROM ghcr.io/transitionalcomputing/signallayer-base@sha256:ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c AS policy-tools
RUN dnf -y install --setopt=install_weak_deps=False selinux-policy-devel setools-console make && dnf clean all

FROM policy-tools AS policy-build
COPY image/platform/selinux /policy
WORKDIR /policy
RUN make -f /usr/share/selinux/devel/Makefile sl_platformd.pp

# Official Fedora 44 bootc base, pinned to its linux/amd64 manifest.
FROM ghcr.io/transitionalcomputing/signallayer-base@sha256:ef8a660e5b1aa24f8b35c43caa57e972f280766c7980440f4490193bf987df2c

ARG SOURCE_REVISION=unknown
ARG BUILD_ID=unknown

LABEL containers.bootc="1" \
      org.opencontainers.image.title="SignalLayerIT CoreOS" \
      org.opencontainers.image.version="0.0.2" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.source="https://github.com/transitionalcomputing/signallayer-coreos"

# Status uses these public crypto files through a fixed OPENSSL_CONF. Preserve
# Fedora's providers/crypto-policy include without permitting cert_t key reads.
RUN set -eu; \
    case "${SOURCE_REVISION}${BUILD_ID}" in \
        *[!A-Za-z0-9._+-]*) echo 'Build metadata must use letters, digits, dot, underscore, plus, or hyphen.' >&2; exit 1 ;; \
    esac; \
    install -d -m 0755 /usr/lib/signallayer; \
    install -d -m 0755 /usr/lib/signallayer/openssl.d; \
    install -m 0644 /etc/pki/tls/openssl.d/pkcs11-provider.conf /usr/lib/signallayer/openssl.d/; \
    sed 's@^\.include /etc/pki/tls/openssl.d$@.include /usr/lib/signallayer/openssl.d@' \
        /etc/pki/tls/openssl.cnf > /usr/lib/signallayer/openssl.cnf; \
    chmod 0644 /usr/lib/signallayer/openssl.cnf; \
    printf '%s\n' \
        'NAME="SignalLayerIT CoreOS"' \
        'VERSION="0.0.2"' \
        'PLATFORM_API_VERSION="0.2"' \
        "SOURCE_REVISION=\"${SOURCE_REVISION}\"" \
        "BUILD_ID=\"${BUILD_ID}\"" \
        > /usr/lib/signallayer/release

COPY --from=platform-build /build/target/release/sl-platformd /usr/bin/sl-platformd
COPY --from=platform-build /build/target/release/corectl /usr/bin/corectl
COPY --from=platform-build /build/target/release/sl-sessiond /usr/bin/sl-sessiond
COPY --from=platform-build /build/target/release/sl-network-observer /usr/bin/sl-network-observer
COPY --from=platform-build /build/target/release/sl-authd /usr/bin/sl-authd
COPY image/platform/sl-platformd.service /usr/lib/systemd/system/sl-platformd.service
COPY image/platform/sl-sessiond.service /usr/lib/systemd/system/sl-sessiond.service
COPY image/platform/sl-network-observer.service /usr/lib/systemd/system/sl-network-observer.service
COPY image/platform/sl-authd.service /usr/lib/systemd/system/sl-authd.service
COPY image/platform/sl-update.service /usr/lib/systemd/system/sl-update.service
COPY image/platform/sl-rollback.service /usr/lib/systemd/system/sl-rollback.service
COPY image/platform/sl-reboot.service /usr/lib/systemd/system/sl-reboot.service
COPY image/platform/sl-bootc-runtime.conf /usr/lib/tmpfiles.d/sl-bootc-runtime.conf
COPY image/platform/sl-sessiond.sysusers /usr/lib/sysusers.d/sl-sessiond.conf
COPY image/platform/sl-network-observer.sysusers /usr/lib/sysusers.d/sl-network-observer.conf
COPY image/platform/sl-authd.sysusers /usr/lib/sysusers.d/sl-authd.conf
COPY image/platform/sl-remoted.sysusers /usr/lib/sysusers.d/sl-remoted.conf
COPY image/platform/sl-console.sysusers /usr/lib/sysusers.d/sl-console.conf
COPY image/platform/org.signallayer.Platform1.conf /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf
COPY image/platform/org.signallayer.Session1.conf /usr/share/dbus-1/system.d/org.signallayer.Session1.conf
COPY image/platform/org.signallayer.NetworkObserver1.conf /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf
COPY image/platform/org.signallayer.Auth1.conf /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf
COPY image/platform/udisks2-polkit.conf /usr/lib/systemd/system/udisks2.service.d/10-polkit-order.conf
COPY --from=policy-build /policy/sl_platformd.pp /usr/share/selinux/packages/sl_platformd.pp
# The pinned bootc base sets store-root=/etc/selinux. Install offline, without
# loading policy in the build container. bootc labels installed files from the
# image's resulting file_contexts; OCI-layer chcon/xattrs are not relied upon.
# Omit inherited standalone module build helpers after installation; retain
# runtime policycoreutils and the supported policy store/backend.
RUN semodule -n -i /usr/share/selinux/packages/sl_platformd.pp && \
    test "$(matchpathcon -n /usr/bin/sl-platformd)" = system_u:object_r:sl_platformd_exec_t:s0 && \
    test "$(matchpathcon -n /usr/bin/sl-sessiond)" = system_u:object_r:sl_sessiond_exec_t:s0 && \
    test "$(matchpathcon -n /usr/bin/sl-network-observer)" = system_u:object_r:sl_network_observer_exec_t:s0 && \
    test "$(matchpathcon -n /usr/bin/sl-authd)" = system_u:object_r:sl_authd_exec_t:s0 && \
    test "$(matchpathcon -n -m dir /var/lib/sl-authd)" = system_u:object_r:sl_authd_var_lib_t:s0 && \
    test "$(matchpathcon -n -m file /var/lib/sl-authd/state.json)" = system_u:object_r:sl_authd_var_lib_t:s0 && \
    test "$(matchpathcon -n /usr/bin/bootc)" = system_u:object_r:install_exec_t:s0 && \
    test "$(matchpathcon -n /usr/lib/systemd/system/sl-update.service)" = system_u:object_r:sl_update_unit_file_t:s0 && \
    test "$(matchpathcon -n /usr/lib/systemd/system/sl-rollback.service)" = system_u:object_r:sl_update_unit_file_t:s0 && \
    test "$(matchpathcon -n /usr/lib/systemd/system/sl-reboot.service)" = system_u:object_r:sl_reboot_unit_file_t:s0 && \
    test "$(matchpathcon -n -m dir /run/ostree)" = system_u:object_r:sl_bootc_runtime_t:s0 && \
    test "$(matchpathcon -n /run/ostree/staged-deployment)" = system_u:object_r:sl_bootc_state_t:s0 && \
    grep -Fqx 'd /run/ostree 0755 root root -' /usr/lib/tmpfiles.d/sl-bootc-runtime.conf && \
    grep -Fqx 'z /run/ostree 0755 root root -' /usr/lib/tmpfiles.d/sl-bootc-runtime.conf && \
    grep -Fqx 'ExecStart=/usr/bin/bootc upgrade --quiet' /usr/lib/systemd/system/sl-update.service && \
    ! grep -Eq -- '--apply|--download-only|ExecStart=.*(sh|bash)' /usr/lib/systemd/system/sl-update.service && \
    grep -Fqx 'ExecStart=/usr/bin/bootc rollback' /usr/lib/systemd/system/sl-rollback.service && \
    ! grep -Eq -- '--apply|--soft-reboot|ExecStart=.*(sh|bash)' /usr/lib/systemd/system/sl-rollback.service && \
    grep -Fqx 'ExecStart=/usr/bin/sl-network-observer' /usr/lib/systemd/system/sl-network-observer.service && \
    grep -Fq '<deny send_destination="org.freedesktop.NetworkManager"/>' /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf && \
    grep -Fq 'send_interface="org.freedesktop.DBus.Properties"' /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf && \
    grep -Fq 'send_member="Get"/>' /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf && \
    grep -Fqx 'ExecStart=/usr/bin/systemctl --no-block reboot' /usr/lib/systemd/system/sl-reboot.service && \
    test "$(grep -c '^Exec' /usr/lib/systemd/system/sl-reboot.service)" = 1 && \
    ! grep -Eq 'ExecStart=.*(sh|bash)' /usr/lib/systemd/system/sl-reboot.service && \
    test "$(grep -c '<policy ' /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf)" = 2 && \
    awk '/<policy context="default">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf | tr -s ' \n' ' ' | grep -Fq '<deny send_destination="org.signallayer.Platform1" send_path="/org/signallayer/Platform1" send_interface="org.signallayer.Platform1" send_member="StartReboot"/>' && \
    awk '/<policy user="root">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf | tr -s ' \n' ' ' | grep -Fq '<allow send_destination="org.signallayer.Platform1" send_path="/org/signallayer/Platform1" send_interface="org.signallayer.Platform1" send_member="StartReboot"/>' && \
    test "$(grep -c 'send_member="StartReboot"' /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf)" = 2 && \
    ! awk '/<policy context="default">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf | tr -s ' \n' ' ' | grep -Eq '<allow [^>]*send_member="StartReboot"' && \
    ! (tr -s ' \n' ' ' < /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf | grep -Eo '<allow [^>]*send_destination[^>]*/>' | grep -vq 'send_member=') && \
    test "$(grep -rl 'StartReboot' /usr/share/dbus-1/system.d /etc/dbus-1 2>/dev/null)" = /usr/share/dbus-1/system.d/org.signallayer.Platform1.conf && \
    grep -Fqx 'ExecStart=/usr/bin/sl-authd' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'User=sl-authd' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'StateDirectory=sl-authd' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'StateDirectoryMode=0700' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'CapabilityBoundingSet=' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'RestrictAddressFamilies=AF_UNIX' /usr/lib/systemd/system/sl-authd.service && \
    grep -Fqx 'u sl-authd - "SignalLayerIT authentication service" /nonexistent /usr/sbin/nologin' /usr/lib/sysusers.d/sl-authd.conf && \
    grep -Fqx 'u sl-remoted - "SignalLayerIT remote management service" /nonexistent /usr/sbin/nologin' /usr/lib/sysusers.d/sl-remoted.conf && \
    grep -Fqx 'u sl-console - "SignalLayerIT local console" /nonexistent /usr/sbin/nologin' /usr/lib/sysusers.d/sl-console.conf && \
    test "$(grep -c '<policy ' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf)" = 6 && \
    test "$(awk '/<policy context="default">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | tr -s ' \n' ' ')" = ' <policy context="default"> <deny own="org.signallayer.Auth1"/> <deny send_destination="org.signallayer.Auth1"/> </policy> ' && \
    test "$(awk '/<policy user="sl-authd">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | tr -s ' \n' ' ')" = ' <policy user="sl-authd"> <allow own="org.signallayer.Auth1"/> </policy> ' && \
    test "$(awk '/<policy user="sl-remoted">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -o 'send_member="[A-Za-z]*"' | sort | tr '\n' ' ')" = 'send_member="ConfirmRecoveryKey" send_member="ConsumePairing" send_member="VerifyPassword" ' && \
    test "$(awk '/<policy user="sl-console">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -o 'send_member="[A-Za-z]*"' | sort | tr '\n' ' ')" = 'send_member="RecoverPassword" send_member="VerifyPassword" ' && \
    test "$(awk '/<policy user="root">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -o 'send_member="[A-Za-z]*"' | sort | tr '\n' ' ')" = 'send_member="CancelPendingPairing" send_member="EnsurePendingPairing" send_member="GetEnrollmentState" send_member="GetPendingPairing" send_member="ResetEnrollment" ' && \
    test "$(awk '/<policy user="sl-sessiond">/,/<\/policy>/' /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -o 'send_member="[A-Za-z]*"' | sort | tr '\n' ' ')" = 'send_member="GetEnrollmentState" ' && \
    test "$(tr -s ' \n' ' ' < /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -Eo '<allow [^>]*send_destination[^>]*/>' | grep -c '^<allow send_destination="org.signallayer.Auth1" send_path="/org/signallayer/Auth1" send_interface="org.signallayer.Auth1" send_member="[A-Za-z]*"/>$')" = 11 && \
    test "$(tr -s ' \n' ' ' < /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf | grep -Eo '<allow [^>]*/>' | wc -l)" = 12 && \
    test "$(grep -rl 'org\.signallayer\.Auth1' /usr/share/dbus-1/system.d /etc/dbus-1 2>/dev/null)" = /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf && \
    ! grep -Eq 'org\.signallayer\.Platform1|StartReboot|StartUpdate|StartRollback' /usr/share/dbus-1/system.d/org.signallayer.Session1.conf /usr/share/dbus-1/system.d/org.signallayer.NetworkObserver1.conf /usr/share/dbus-1/system.d/org.signallayer.Auth1.conf && \
    test "$(matchpathcon -n /usr/lib/signallayer/release)" = system_u:object_r:sl_platformd_release_t:s0 && \
    test "$(matchpathcon -n -m dir /ostree)" = system_u:object_r:sl_platformd_ostree_t:s0 && \
    test "$(matchpathcon -n -m file /ostree/lock)" = system_u:object_r:sl_platformd_lock_t:s0 && \
    rm -f /usr/bin/semodule_expand /usr/bin/semodule_link \
          /usr/bin/semodule_package /usr/bin/semodule_unpackage \
          /usr/share/selinux/devel/include/services/container.if \
          /usr/share/selinux/devel/include/distributed/passt.if && \
    rmdir /usr/share/selinux/devel/include/services \
          /usr/share/selinux/devel/include/distributed \
          /usr/share/selinux/devel/include /usr/share/selinux/devel
RUN install -d /usr/lib/systemd/system/multi-user.target.wants && \
    ln -s ../sl-platformd.service /usr/lib/systemd/system/multi-user.target.wants/sl-platformd.service && \
    ln -s ../sl-sessiond.service /usr/lib/systemd/system/multi-user.target.wants/sl-sessiond.service && \
    ln -s ../sl-network-observer.service /usr/lib/systemd/system/multi-user.target.wants/sl-network-observer.service && \
    ln -s ../sl-authd.service /usr/lib/systemd/system/multi-user.target.wants/sl-authd.service

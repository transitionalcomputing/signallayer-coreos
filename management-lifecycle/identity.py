"""P3-1b source-only identity provisioner. No CLI, installation or service.

The only public mutation entry point takes no arguments and uses fixed paths.
Private fixture stores exercise real parsing/allocation/atomic file operations;
they do not certify installed Fedora behavior or authorize integration.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import grp
import json
import os
import pwd
from pathlib import PurePosixPath
import re
import secrets
import stat

NAME = "sl-management"
HOME = "/var/lib/signallayer/management-runtime/home"
SHELL = "/usr/sbin/nologin"
RECOVERY = "var/lib/signallayer/runtime-recovery"
METADATA = RECOVERY + "/identity.json"
LOCK = RECOVERY + "/identity.lock"
FILES = ("etc/group", "etc/gshadow", "etc/shadow", "etc/passwd", "etc/subuid", "etc/subgid")
STATE = ("var/lib/signallayer/management", "var/lib/signallayer/management-runtime")
MAX_ID = 2**32 - 2  # (uid_t)-1 is not an identity.
COUNT = 65536
LIMIT = 4 * 1024 * 1024
ACCOUNT = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.-]*\$?\Z")


class IdentityError(RuntimeError):
    """Fail-closed refusal; messages deliberately exclude account credentials."""


def _number(value: str, maximum=MAX_ID) -> int:
    if len(value) > 10 or not re.fullmatch(r"0|[1-9][0-9]*", value) or int(value) > maximum:
        raise IdentityError("invalid or overflowing numeric identity")
    return int(value)


def _digest(value: bytes | None) -> str | None:
    return None if value is None else hashlib.sha256(value).hexdigest()


def _lines(data: bytes | None, fields: int) -> dict[str, list[str]]:
    if data is None:
        return {}
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise IdentityError("invalid account-file encoding") from error
    if "\r" in text or "\x00" in text or (text and not text.endswith("\n")):
        raise IdentityError("partial or malformed account file")
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        row = line.split(":")
        if len(row) != fields or not ACCOUNT.fullmatch(row[0]) or row[0] in result:
            raise IdentityError("malformed or duplicate account record")
        result[row[0]] = row
    return result


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


@dataclass(frozen=True)
class Identity:
    uid: int
    gid: int
    subuid: int
    subgid: int
    count: int = COUNT

    def __post_init__(self):
        values = (self.uid, self.gid, self.subuid, self.subgid, self.count)
        if any(type(value) is not int for value in values):
            raise IdentityError("invalid identity metadata types")
        if not (100 <= self.uid <= 999 and 100 <= self.gid <= 999):
            raise IdentityError("invalid system identity metadata")
        if self.count != COUNT or any(start < 100000 or start % COUNT or start + COUNT - 1 > MAX_ID
                                      for start in (self.subuid, self.subgid)):
            raise IdentityError("invalid subordinate identity metadata")

    @property
    def home(self):
        return HOME


@dataclass
class Snapshot:
    raw: dict[str, bytes | None]
    passwd: dict[str, list[str]]
    groups: dict[str, list[str]]
    shadow: dict[str, list[str]]
    gshadow: dict[str, list[str]]
    subuids: dict[str, tuple[int, int]]
    subgids: dict[str, tuple[int, int]]


def _subids(data: bytes | None, users: dict[str, list[str]]) -> dict[str, tuple[int, int]]:
    # Numeric owners are resolved through the same local passwd snapshot.
    if data is None:
        return {}
    try:
        text = data.decode("ascii")
    except UnicodeError as error:
        raise IdentityError("invalid subordinate-ID encoding") from error
    if "\r" in text or "\x00" in text or (text and not text.endswith("\n")):
        raise IdentityError("partial subordinate-ID record")
    by_uid = {int(row[2]): name for name, row in users.items()}
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        row = line.split(":")
        if len(row) != 3:
            raise IdentityError("malformed subordinate-ID record")
        owner = by_uid.get(_number(row[0])) if row[0].isdigit() else row[0]
        if owner not in users:
            raise IdentityError("subordinate-ID owner missing")
        start, count = _number(row[1]), _number(row[2])
        if not start or not count or start + count - 1 > MAX_ID:
            raise IdentityError("empty, root or overflowing subordinate-ID extent")
        extent = (start, start + count - 1)
        if owner in result or any(_overlap(extent, previous) for previous in result.values()):
            raise IdentityError("duplicate or overlapping subordinate-ID extent")
        result[owner] = extent
    return result


def read_validate(raw: dict[str, bytes | None]) -> Snapshot:
    """Parse a complete local snapshot; never read NSS or mutate the machine."""
    if set(raw) != set(FILES) or any(raw[path] is None for path in FILES[:4]):
        raise IdentityError("missing account database")
    users = _lines(raw["etc/passwd"], 7)
    groups = _lines(raw["etc/group"], 4)
    shadow = _lines(raw["etc/shadow"], 9)
    gshadow = _lines(raw["etc/gshadow"], 4)
    for rows, index in ((users, 2), (groups, 2)):
        ids = [_number(row[index]) for row in rows.values()]
        if len(ids) != len(set(ids)):
            raise IdentityError("duplicate numeric account identity")
    group_ids = {_number(row[2]) for row in groups.values()}
    if any(_number(row[3]) not in group_ids for row in users.values()):
        raise IdentityError("missing primary group")
    for row in groups.values():
        members = row[3].split(",") if row[3] else []
        if len(members) != len(set(members)) or any(name not in users for name in members):
            raise IdentityError("invalid supplementary group member")
    for row in gshadow.values():
        for field in row[2:]:
            members = field.split(",") if field else []
            if len(members) != len(set(members)) or any(name not in users for name in members):
                raise IdentityError("invalid group administrator/member")
    for row in shadow.values():
        for field in row[2:]:
            if field:
                _number(field)
    if set(shadow) != set(users) or set(gshadow) != set(groups):
        raise IdentityError("partial passwd/shadow or group/gshadow database")
    subuids = _subids(raw["etc/subuid"], users)
    subgids = _subids(raw["etc/subgid"], users)
    # Primary IDs must never be handed out as subordinate IDs, in either space.
    occupied = {_number(row[2]) for row in users.values()} | group_ids
    if any(start <= value <= end for table in (subuids, subgids)
           for start, end in table.values() for value in occupied):
        raise IdentityError("subordinate mapping overlaps a live primary identity")
    return Snapshot(raw, users, groups, shadow, gshadow, subuids, subgids)


def _extent(snapshot: Snapshot) -> int:
    ranges = list(snapshot.subuids.values()) + list(snapshot.subgids.values())
    occupied = [int(row[2]) for row in snapshot.passwd.values()] + [int(row[2]) for row in snapshot.groups.values()]
    start = ((100000 + COUNT - 1) // COUNT) * COUNT
    # Jump whole extents, rather than iterating over a 32-bit address space.
    for low, high in sorted(ranges + [(value, value) for value in occupied]):
        if _overlap((start, start + COUNT - 1), (low, high)):
            start = ((high + 1 + COUNT - 1) // COUNT) * COUNT
    if start + COUNT - 1 > MAX_ID:
        raise IdentityError("no free subordinate-ID extent")
    return start


def plan(snapshot: Snapshot) -> Identity:
    """Deterministic machine-local choice, never adopt an unrecorded account."""
    if any(NAME in table for table in (snapshot.passwd, snapshot.groups, snapshot.shadow,
                                      snapshot.gshadow, snapshot.subuids, snapshot.subgids)):
        raise IdentityError("ambiguous pre-existing sl-management; recovery record required")
    occupied = {int(row[2]) for row in snapshot.passwd.values()} | {int(row[2]) for row in snapshot.groups.values()}
    ranges = list(snapshot.subuids.values()) + list(snapshot.subgids.values())
    available = [value for value in range(999, 99, -1)
                 if value not in occupied and not any(start <= value <= end for start, end in ranges)]
    if not available:
        raise IdentityError("no free machine-local system UID/GID")
    start = _extent(snapshot)
    return Identity(available[0], available[0], start, start)


def _records(identity: Identity) -> dict[str, bytes]:
    return {
        "etc/group": f"{NAME}:x:{identity.gid}:\n".encode(),
        "etc/gshadow": f"{NAME}:!::\n".encode(),
        "etc/shadow": f"{NAME}:!:0:0:99999:7:::\n".encode(),
        "etc/passwd": f"{NAME}:x:{identity.uid}:{identity.gid}:SignalLayer management:{HOME}:{SHELL}\n".encode(),
        "etc/subuid": f"{NAME}:{identity.subuid}:{identity.count}\n".encode(),
        "etc/subgid": f"{NAME}:{identity.subgid}:{identity.count}\n".encode(),
    }


def _verify(snapshot: Snapshot, identity: Identity):
    row = snapshot.passwd.get(NAME)
    group = snapshot.groups.get(NAME)
    shadow = snapshot.shadow.get(NAME)
    gshadow = snapshot.gshadow.get(NAME)
    if (row is None or row[1] != "x" or int(row[2]) != identity.uid
            or int(row[3]) != identity.gid or row[5:] != [HOME, SHELL]
            or group is None or group[1] != "x" or int(group[2]) != identity.gid or group[3]
            or shadow is None or not shadow[1].startswith(("!", "*"))
            or gshadow is None or not gshadow[1].startswith(("!", "*")) or any(gshadow[2:])):
        raise IdentityError("locked account identity/shell/credentials drift")
    if any(NAME in row[3].split(",") for row in snapshot.groups.values()):
        raise IdentityError("unauthorized supplementary group membership")
    if any(NAME in field.split(",") for row in snapshot.gshadow.values() for field in row[2:]):
        raise IdentityError("unauthorized group administrator/member")
    if snapshot.subuids.get(NAME) != (identity.subuid, identity.subuid + identity.count - 1) or snapshot.subgids.get(NAME) != (identity.subgid, identity.subgid + identity.count - 1):
        raise IdentityError("accepted subordinate mapping drift")


class _Store:
    """FD-anchored fixed files. Fixture construction is private, not a CLI/API.

    Live entry always uses / and uid/gid 0. Tests substitute only a disposable
    root and its actual owning UID/GID; this does not prove production labels.
    """
    def __init__(self, root: str, uid: int, gid: int):
        self.uid, self.gid = uid, gid
        self.fds = ExitStack()
        try:
            self.root = self._open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._check(self.root, directory=True)
        except BaseException:
            self.close()
            raise

    def _open(self, path, flags, mode=0o600, *, parent=None):
        fd = os.open(path, flags | os.O_CLOEXEC, mode, dir_fd=parent)
        self.fds.callback(os.close, fd)
        return fd

    def close(self):
        self.fds.close()

    def _check(self, fd, *, directory=False, private=False):
        info = os.fstat(fd)
        correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        forbidden = 0o7022 | (0o077 if private else 0) | (0 if directory else 0o111)
        if (not correct_type or info.st_uid != self.uid or info.st_gid != self.gid
                or info.st_mode & forbidden or (not directory and info.st_nlink != 1)):
            raise IdentityError("untrusted file type, ownership, mode or hardlink")
        if not directory and "security.capability" in os.listxattr(fd):
            raise IdentityError("unexpected identity-file capability")

    def parent(self, path: str, *, create=False):
        # Every caller supplies a module-owned constant, never user input.
        parts = PurePosixPath(path).parts
        fd = self.root
        for index, component in enumerate(parts[:-1]):
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            fd = self._open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent=fd)
            self._check(fd, directory=True, private=("/".join(parts[:index+1]) == RECOVERY))
        return fd, parts[-1]

    def read(self, path: str):
        parent, name = self.parent(path)
        try:
            fd = self._open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, parent=parent)
        except FileNotFoundError:
            return None
        self._check(fd, private=path in ("etc/shadow", "etc/gshadow", METADATA))
        before = os.fstat(fd)
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, LIMIT + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > LIMIT:
                raise IdentityError("oversized identity state")
        after = os.fstat(fd)
        if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size):
            raise IdentityError("identity file changed during read")
        self._check(fd, private=path in ("etc/shadow", "etc/gshadow", METADATA))
        return b"".join(chunks)

    def locked(self):
        parent, name = self.parent(LOCK, create=True)
        fd = self._open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, parent=parent)
        self._check(fd, private=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            parent, name = self.parent("etc/.pwd.lock")
            pwd = self._open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, parent=parent)
            self._check(pwd, private=True)
            fcntl.lockf(pwd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise IdentityError("identity lock unavailable") from error

    def state_exists(self):
        for path in STATE:
            parent, name = self.parent(path)
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            return True
        return False

    def replace(self, path: str, data: bytes, expected: str | None):
        if _digest(self.read(path)) != expected:
            raise IdentityError("concurrent identity-file change; recovery required")
        parent, name = self.parent(path)
        mode = 0o600 if path in (METADATA, "etc/shadow", "etc/gshadow") else 0o644
        attrs = {}
        try:
            original = self._open(name, os.O_RDONLY | os.O_NOFOLLOW, parent=parent)
        except FileNotFoundError:
            pass
        else:
            self._check(original, private=path in (METADATA, "etc/shadow", "etc/gshadow"))
            mode = stat.S_IMODE(os.fstat(original).st_mode)
            for key in os.listxattr(original):
                if key == "security.capability":
                    raise IdentityError("unexpected identity-file capability")
                attrs[key] = os.getxattr(original, key)
        temporary = ".sl-identity-" + secrets.token_hex(16)
        fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, parent=parent)
        try:
            os.fchown(fd, self.uid, self.gid)
            os.fchmod(fd, mode)
            for key, value in attrs.items():
                os.setxattr(fd, key, value)
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                if not count:
                    raise IdentityError("incomplete identity-file write")
                view = view[count:]
            os.fsync(fd)
            if _digest(self.read(path)) != expected:
                raise IdentityError("concurrent identity-file change; recovery required")
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
        self.after_write(path)

    def check_sources(self):
        """Fixture store has only the explicitly supplied local databases."""

    def check_choice(self, chosen):
        """Host subclass corroborates local allocation with actual NSS."""

    def after_write(self, path):
        """Private no-op failure-injection seam; never selected by caller input."""


def _nss_policy(data):
    if data is None:
        raise IdentityError("missing NSS policy; local identity authority unproven")
    guarded = {"passwd", "group", "shadow", "gshadow", "subid", "initgroups"}
    try:
        entries = {}
        for line in data.decode("ascii").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, separator, value = line.partition(":")
            database = key.strip().lower()
            if database in guarded:
                if not separator or database in entries:
                    raise IdentityError(f"malformed or duplicate NSS {database} policy")
                # libsubid recognizes subid case-insensitively; never ignore a
                # case variant that another NSS consumer might interpret.
                if key.strip() != database:
                    raise IdentityError(f"unsupported NSS database casing: {database}")
                entries[database] = value.split()
                if any(token.lower() == "altfiles" for token in entries[database]):
                    raise IdentityError(
                        f"NSS altfiles in {database} requires /usr/lib/passwd and "
                        "/usr/lib/group integration and deployment collision checks")
            elif not separator and line.split()[0].lower() in guarded:
                raise IdentityError("malformed NSS identity declaration")
        ordinary = (("files",), ("files", "systemd"))
        for database in ("passwd", "group", "shadow", "gshadow"):
            if database == "gshadow" and database not in entries:
                continue
            supported = ordinary + (("files", "[SUCCESS=merge]", "systemd"),) if database == "group" else ordinary
            if tuple(entries.get(database, ())) not in supported:
                raise IdentityError(f"unsupported NSS {database} provider/action; integration review required")
        # shadow-utils 4.19 lib/nss.c returns its built-in files backend when
        # subid is absent. Unknown plugins/actions must still be refused.
        if "subid" in entries and entries["subid"] != ["files"]:
            raise IdentityError("NSS subid must be absent or exactly files")
        if "initgroups" in entries:
            sources = entries["initgroups"]
            group_sources = {token for token in entries["group"] if not token.startswith("[")}
            if not sources or len(sources) != len(set(sources)) or not set(sources) <= group_sources:
                raise IdentityError("NSS initgroups must be a unique subset of configured group sources")
    except UnicodeError as error:
        raise IdentityError("malformed NSS identity policy") from error


class _HostStore(_Store):
    def __init__(self):
        super().__init__("/", 0, 0)

    def check_sources(self):
        # Do not allocate against an incomplete remote/directory-service view.
        # No provider configuration is changed; unsupported policy fails closed.
        try:
            policy = self.read("etc/nsswitch.conf")
        except OSError as error:
            raise IdentityError(
                f"cannot safely read etc/nsswitch.conf (errno {error.errno}); "
                "authselect symlinks remain unsupported") from error
        except IdentityError as error:
            raise IdentityError(f"untrusted etc/nsswitch.conf: {error}") from error
        _nss_policy(policy)

    def check_choice(self, chosen):
        users, groups = pwd.getpwall(), grp.getgrall()
        for lookup, number in ((pwd.getpwuid, chosen.uid), (grp.getgrgid, chosen.gid)):
            try:
                entry = lookup(number)
            except KeyError:
                continue
            name = entry.pw_name if hasattr(entry, "pw_name") else entry.gr_name
            if name != NAME:
                raise IdentityError("NSS identity collision; local allocation refused")
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                entry = lookup(NAME)
            except KeyError:
                continue
            if ((hasattr(entry, "pw_uid") and (entry.pw_uid != chosen.uid or entry.pw_gid != chosen.gid))
                    or (hasattr(entry, "gr_gid") and entry.gr_gid != chosen.gid)):
                raise IdentityError("NSS name collision; local allocation refused")
        ranges = ((chosen.subuid, chosen.subuid+COUNT-1), (chosen.subgid, chosen.subgid+COUNT-1))
        if (any(low <= entry.pw_uid <= high for entry in users for low, high in ranges)
                or any(low <= entry.gr_gid <= high for entry in groups for low, high in ranges)):
            raise IdentityError("NSS primary identity overlaps proposed mappings")
        if any(NAME in entry.gr_mem for entry in groups):
            raise IdentityError("NSS supplementary membership refused")
        # NSS group enumeration does not implement SUCCESS=merge semantics.
        # glibc accepts a supplied name even before the local account exists.
        try:
            effective = os.getgrouplist(NAME, chosen.gid)
        except OSError as error:
            raise IdentityError("NSS effective membership lookup failed for sl-management") from error
        if any(type(gid) is not int for gid in effective) or set(effective) != {chosen.gid}:
            raise IdentityError("NSS effective supplementary membership refused")


def _encode(record):
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _metadata(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise IdentityError("duplicate recovery metadata key")
            result[key] = value
        return result
    try:
        record = json.loads(data, object_pairs_hook=unique)
        if type(record) is not dict or type(record.get("schema")) is not int or record["schema"] != 1:
            raise IdentityError("unsupported identity recovery schema")
        phase = record.get("phase")
        keys = {"schema", "phase", "identity"} | ({"files"} if phase == "prepared" else set())
        if set(record) != keys or phase not in ("prepared", "committed"):
            raise IdentityError("invalid identity recovery phase")
        identity = Identity(**record["identity"])
        if phase == "prepared":
            if set(record["files"]) != set(FILES):
                raise IdentityError("incomplete transaction intent")
            for item in record["files"].values():
                if set(item) != {"before", "after"} or not re.fullmatch(r"[0-9a-f]{64}", item["after"]):
                    raise IdentityError("invalid transaction digest")
                if item["before"] is not None and not re.fullmatch(r"[0-9a-f]{64}", item["before"]):
                    raise IdentityError("invalid transaction digest")
        return record, identity
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise IdentityError("malformed identity recovery metadata") from error


def _provision(store: _Store) -> Identity:
    store.locked()
    store.check_sources()
    raw = {path: store.read(path) for path in FILES}
    saved = store.read(METADATA)
    if saved is None:
        if store.state_exists():
            raise IdentityError("runtime/application state exists without accepted identity")
        identity = plan(read_validate(raw))
        store.check_choice(identity)
        additions = _records(identity)
        final = {path: (raw[path] or b"") + additions[path] for path in FILES}
        _verify(read_validate(final), identity)
        record = {"schema": 1, "phase": "prepared", "identity": asdict(identity),
                  "files": {path: {"before": _digest(raw[path]), "after": _digest(final[path])} for path in FILES}}
        store.replace(METADATA, _encode(record), None)
    else:
        record, identity = _metadata(saved)
        if record["phase"] == "committed":
            _verify(read_validate(raw), identity)
            store.check_choice(identity)
            return identity
        additions = _records(identity)
        final = {}
        for path, item in record["files"].items():
            digest = _digest(raw[path])
            if digest == item["after"]:
                final[path] = raw[path]
            elif digest == item["before"]:
                final[path] = (raw[path] or b"") + additions[path]
                if _digest(final[path]) != item["after"]:
                    raise IdentityError("transaction intent mismatch")
            else:
                raise IdentityError("interrupted identity transaction conflicts; recovery required")
        _verify(read_validate(final), identity)
        store.check_choice(identity)
        if store.state_exists() and any(raw[path] != final[path] for path in FILES):
            raise IdentityError("partial identity with runtime/application state; recovery required")
    for path in FILES:
        if raw[path] != final[path]:
            store.replace(path, final[path], record["files"][path]["before"])
    # Verify the complete transaction before publishing durable accepted values.
    _verify(read_validate({path: store.read(path) for path in FILES}), identity)
    # Corroborate effective membership again now that the account exists.
    store.check_choice(identity)
    committed = {"schema": 1, "phase": "committed", "identity": asdict(identity)}
    store.replace(METADATA, _encode(committed), _digest(_encode(record)))
    return identity


def provision() -> Identity:
    """Fixed root-only entry point for a future approved native integration.

    Not wired into any service, build or executable in P3-1b. No parameters,
    subprocesses, dynamic commands, account names or configurable paths.
    """
    if os.geteuid() != 0 or os.getuid() != 0:
        raise IdentityError("identity provisioning requires host root")
    store = _HostStore()
    try:
        return _provision(store)
    finally:
        store.close()

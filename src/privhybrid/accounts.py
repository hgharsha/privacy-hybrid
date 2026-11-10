"""Accounts and encrypted per-user storage (PII-STANDARD.md: private data stays on this Mac, and now on disk only sealed).

Email is the login name. It is never sent anywhere and never written in plain text: the folder name is a salted hash of
it, and the address itself lives inside the user's encrypted profile.
Password -> scrypt -> 64 bytes: the first half proves the password, the second half is the AES-GCM key for that user's
files (library, search index, chats). The key exists only in memory while logged in. A lost password means lost data:
there is no recovery and no mail server.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import time
from pathlib import Path
from typing import Any, Optional

from . import fsutil
from . import filelock
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
MIN_PASSWORD, MAX_PASSWORD, MAX_USERS = 8, 256, 20
SCRYPT = {"n": 2 ** 16, "r": 8, "p": 2, "length": 64}  # this Python build has no hashlib.scrypt; 64 MiB, one of OWASP's equivalent settings
LEGACY_KDF = {"n": 2 ** 15, "r": 8, "p": 1}  # accounts made before the parameters were stored in meta.json


class AuthError(RuntimeError):
    """Wrong credentials, bad input, or registration refused. The message is safe to show."""


class Conflict(RuntimeError):
    """The stored file changed since this copy was read (another session, process or restore). The write was refused; nothing was lost."""


PERMISSIONS = ("local", "cloud", "web", "upload", "library", "scheduled", "admin")
ADMIN_PERMS = {k: True for k in PERMISSIONS}
LEGACY_PERMS = {**ADMIN_PERMS, "admin": False}  # accounts that existed before permissions: nothing they could do is taken away
NEW_USER_PERMS = {"local": True, "cloud": False, "web": False, "upload": True, "library": True, "scheduled": False, "admin": False}
DEFAULT_LIMITS = {"cloud_per_day": 200, "chats_per_minute": 20, "uploads_per_minute": 20, "storage_mb": 200}
INVITE_TTL = 7 * 24 * 3600


def _norm(email: str) -> str:
    return email.strip().lower()


def _kdf_of(meta: dict) -> dict:
    k = meta.get("kdf")
    if isinstance(k, dict) and all(isinstance(k.get(x), int) and k[x] > 0 for x in ("n", "r", "p")) and k["n"] & (k["n"] - 1) == 0 and k["n"] <= 2 ** 20:
        return {"n": k["n"], "r": k["r"], "p": k["p"]}
    return dict(LEGACY_KDF)


def _derive(password: str, salt: bytes, kdf: "dict | None" = None) -> "tuple[bytes, bytes]":
    dk = Scrypt(salt=salt, length=SCRYPT["length"], **(kdf or {k: SCRYPT[k] for k in ("n", "r", "p")})).derive(password.encode("utf-8"))
    return hashlib.sha256(dk[:32]).digest(), dk[32:]  # (verifier, file key)


class Account:
    def __init__(self, uid: str, folder: Path, key: bytes, email: str) -> None:
        self.id, self.folder, self.email = uid, folder, email
        self._aead = AESGCM(key)

    def _read(self, name: str) -> "tuple[Any, int]":
        """(object, version). Files written before versions existed read as version 0."""
        blob = (self.folder / name).read_bytes()
        try:
            obj = json.loads(self._aead.decrypt(blob[:12], blob[12:], name.encode()))
        except (InvalidTag, ValueError):
            raise AuthError(f"{name} could not be decrypted")
        if isinstance(obj, dict) and set(obj) == {"__pv", "v", "d"}:
            return obj["d"], int(obj["v"])
        return obj, 0

    def save(self, name: str, obj: Any, base: "int | None" = None, rekey: bool = False) -> int:
        """Write sealed. With `base` (the version this copy was read at) a file that has moved on is refused with Conflict instead of overwritten.
        Returns the new version."""
        nonce = secrets.token_bytes(12)
        with filelock.locked(self.folder.parent / f".{self.folder.name}.lock"):  # across threads and processes: the version check and the replace are one step
            try:
                cur = self._read(name)[1]
            except OSError:
                cur = 0
            except AuthError:
                if not rekey:
                    raise  # the file is sealed under another key: only a password change may replace it
                cur = 0
            if base is not None and cur != base:
                raise Conflict(name)
            ver = cur + 1
            blob = nonce + self._aead.encrypt(nonce, json.dumps({"__pv": 1, "v": ver, "d": obj}).encode("utf-8"), name.encode())
            tmp = self.folder / f".{name}.{secrets.token_hex(4)}.tmp"
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as fh:  # never world-readable, even briefly
                fh.write(blob)
            fsutil.replace(tmp, self.folder / name)
        return ver

    def load(self, name: str, default: Any) -> Any:
        return self.load_v(name, default)[0]

    def load_v(self, name: str, default: Any) -> "tuple[Any, int]":
        try:
            return self._read(name)
        except OSError:
            return default, 0




class Store:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        fsutil.private(self.root, 0o700)
        salt_file = self.root / "install_salt"
        if not salt_file.exists():
            salt_file.write_bytes(secrets.token_bytes(16))
            fsutil.private(salt_file, 0o600)
        self._salt = salt_file.read_bytes()
        self._sweep_temp()
        self._recover_rekey()
        self._migrate_access()

    def _recover_rekey(self) -> None:
        """A password change that was interrupted (process killed) left `<id>.rekeying` and a `<id>.bak` copy of the account as it was before.
        The change is only complete once the marker is gone, so an interrupted one is rolled back to that consistent earlier state."""
        with self._store_lock():
            for marker in self.root.glob("*.rekeying"):
                uid = marker.name[:-len(".rekeying")]
                folder, backup = self.root / uid, self.root / f"{uid}.bak"
                if backup.exists():
                    shutil.rmtree(folder, ignore_errors=True)
                    fsutil.replace(backup, folder)
                marker.unlink(missing_ok=True)

    def _store_lock(self):
        """One lock for the access records, the administrator file and registrations, across threads and processes (taken before any account lock)."""
        return filelock.locked(self.root / ".store.lock")

    def _sweep_temp(self) -> None:
        """Abandoned temp files from a crashed write are removed (older than an hour)."""
        cutoff = time.time() - 3600
        for f in self.root.glob("*/.*.tmp"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
            except OSError:
                pass

    # --- access records: who may do what (hashed ids and flags only; nothing personal) --------------------------

    @property
    def _access_file(self) -> Path:
        return self.root / "access.json"

    def access(self) -> dict:
        try:
            data = json.loads(self._access_file.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {"registration": "invite", "users": {}, "invites": {}}

    def _write_access(self, data: dict) -> None:
        tmp = self.root / f".access.{secrets.token_hex(4)}.tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
            json.dump(data, fh)
        fsutil.replace(tmp, self._access_file)

    def _migrate_access(self) -> None:
        """Accounts that existed before permissions keep everything they could do (a record is written so the administrator can see and change it).
        Nothing is deleted or re-encrypted. Registration becomes invitation-only unless the environment says PRIVHYBRID_REGISTRATION=open."""
        with self._store_lock():
            data = self.access()
            changed = False
            for p in self.root.iterdir():
                if p.is_dir() and not p.name.endswith(".bak") and (p / "meta.json").exists() and p.name not in data["users"]:
                    data["users"][p.name] = {"perms": dict(LEGACY_PERMS), "disabled": False, "limits": {}}
                    changed = True
            boss = self.admin_id()
            for uid, rec in data["users"].items():
                if uid != boss and rec.get("perms", {}).get("admin"):
                    rec["perms"]["admin"], changed = False, True  # a leftover flag from before a transfer
            mode = os.environ.get("PRIVHYBRID_REGISTRATION", "")
            if mode in ("open", "invite") and data.get("registration") != mode:
                data["registration"], changed = mode, True
            if changed or not self._access_file.exists():
                self._write_access(data)

    def record(self, uid: str) -> dict:
        return self.access()["users"].get(uid) or {"perms": dict(LEGACY_PERMS), "disabled": False, "limits": {}}

    def perms(self, uid: str) -> dict:
        rec = self.record(uid)
        if rec.get("disabled"):
            return {k: False for k in PERMISSIONS}
        perms = {**{k: False for k in PERMISSIONS}, **rec.get("perms", {})}
        perms["admin"] = uid == self.admin_id()  # only the current administrator id; a stale stored flag counts for nothing
        return perms

    def limits(self, uid: str) -> dict:
        return {**DEFAULT_LIMITS, **self.record(uid).get("limits", {})}

    def set_access(self, uid: str, perms: "dict | None" = None, limits: "dict | None" = None, disabled: "bool | None" = None) -> None:
        with self._store_lock():
            data = self.access()
            rec = data["users"].setdefault(uid, {"perms": dict(NEW_USER_PERMS), "disabled": False, "limits": {}})
            if perms:
                rec["perms"].update({k: bool(v) for k, v in perms.items() if k in PERMISSIONS and k != "admin"})
            if limits:
                rec["limits"].update({k: int(v) for k, v in limits.items() if k in DEFAULT_LIMITS and int(v) >= 0})
            if disabled is not None:
                if disabled and uid == self.admin_id():
                    raise AuthError("The administrator cannot be disabled; transfer the role first")
                rec["disabled"] = bool(disabled)
            self._write_access(data)

    def registration_mode(self) -> str:
        return self.access().get("registration", "invite")

    def set_registration(self, mode: str) -> None:
        if mode not in ("open", "invite"):
            raise AuthError("Registration is 'open' or 'invite'")
        with self._store_lock():
            data = self.access()
            data["registration"] = mode
            self._write_access(data)

    def create_invite(self, perms: "dict | None" = None) -> str:
        """A single-use code, valid for a week. Only its hash is stored."""
        token = secrets.token_urlsafe(18)
        with self._store_lock():
            data = self.access()
            now = time.time()
            data["invites"] = {h: v for h, v in data.get("invites", {}).items() if v["exp"] > now}
            data["invites"][hashlib.sha256(token.encode()).hexdigest()] = {"exp": now + INVITE_TTL, "perms": {k: bool(v) for k, v in (perms or {}).items() if k in PERMISSIONS and k != "admin"}}
            self._write_access(data)
        return token

    def _take_invite(self, token: str) -> "dict | None":
        with self._store_lock():
            data = self.access()
            h = hashlib.sha256(token.strip().encode()).hexdigest()
            inv = data.get("invites", {}).pop(h, None)
            if inv is None or inv["exp"] < time.time():
                return None
            self._write_access(data)
            return inv

    def _write_admin(self, uid: str) -> None:
        tmp = self.root / f".admin.{secrets.token_hex(4)}.tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
            fh.write(uid)
        fsutil.replace(tmp, self.root / "admin")

    def transfer_admin(self, acct: "Account", password: str, to_email: str) -> None:
        """The check, both permission records and the administrator file change in one step under the store lock, so two simultaneous transfers
        cannot leave two administrators (the second one fails its check) or none."""
        self.login(acct.email, password)  # the current administrator proves who they are
        target = self.user_id(to_email)
        with self._store_lock():
            if acct.id != self.admin_id():
                raise AuthError("Only the administrator can transfer the role")
            if target == acct.id:
                raise AuthError("You are already the administrator")
            if not (self.root / target / "meta.json").exists() or self.record(target).get("disabled"):
                raise AuthError("That account does not exist or is disabled")
            data = self.access()
            data["users"].setdefault(target, {"perms": dict(NEW_USER_PERMS), "disabled": False, "limits": {}})["perms"].update(ADMIN_PERMS)
            old = data["users"].setdefault(acct.id, {"perms": dict(NEW_USER_PERMS), "disabled": False, "limits": {}})
            old["perms"]["admin"] = False  # the former administrator keeps their other rights but not this one
            self._write_access(data)
            self._write_admin(target)

    def user_id(self, email: str) -> str:
        return hashlib.sha256(self._salt + _norm(email).encode()).hexdigest()[:24]

    @staticmethod
    def _created(folder: Path) -> float:
        """When the account was made. Older accounts have no stamp, so their file time stands in (a password change used to refresh it)."""
        meta = folder / "meta.json"
        try:
            return float(json.loads(meta.read_text())["created"])
        except (OSError, ValueError, KeyError, TypeError):
            return meta.stat().st_mtime

    def admin_id(self) -> str:
        """The first account on this install owns shared settings and the audit log. Older installs: the oldest account."""
        f = self.root / "admin"
        try:
            uid = f.read_text().strip()
            if uid and (self.root / uid / "meta.json").exists():
                return uid
        except OSError:
            pass  # missing, or the admin deleted their account: the oldest remaining account takes over
        folders = [p for p in self.root.iterdir() if p.is_dir() and not p.name.endswith(".bak") and (p / "meta.json").exists()]
        if not folders:
            return ""
        uid = min(folders, key=self._created).name
        with self._store_lock():
            try:  # another process may have chosen one while we waited
                cur = f.read_text().strip()
                if cur and (self.root / cur / "meta.json").exists():
                    return cur
            except OSError:
                pass
            self._write_admin(uid)
        return uid

    def count(self) -> int:
        return sum(1 for p in self.root.iterdir() if p.is_dir() and not p.name.endswith(".bak"))

    def register(self, email: str, password: str, invite: str = "", by_admin: bool = False, from_loopback: bool = True) -> Account:
        """The first account on an install becomes the administrator (and may need PRIVHYBRID_SETUP_TOKEN as `invite`). After that an account needs
        an invitation code, an administrator, or registration set to 'open'. The check and the creation are one step, so two simultaneous
        first registrations cannot both become administrator."""
        email = _norm(email)
        if not EMAIL_RE.match(email):
            raise AuthError("Enter a valid email address")
        if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
            raise AuthError(f"Password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters")
        uid = self.user_id(email)
        folder = self.root / uid
        salt = secrets.token_bytes(16)
        verifier, key = _derive(password, salt)  # slow part, outside the lock
        with self._store_lock():
            if folder.exists():
                raise AuthError("That email is already registered")
            first = self.count() == 0
            perms = dict(NEW_USER_PERMS)
            if first:
                token = os.environ.get("PRIVHYBRID_SETUP_TOKEN", "")
                if token and not hmac.compare_digest(token, invite.strip()):
                    raise AuthError("This server needs its setup code to create the first account")
                if not token and not from_loopback:  # no setup code: only someone at this computer may claim the administrator role
                    raise AuthError("Create the first account from the computer running the app, or set PRIVHYBRID_SETUP_TOKEN")
                perms = dict(ADMIN_PERMS)
            elif not by_admin and self.registration_mode() != "open":
                inv = self._take_invite(invite) if invite.strip() else None
                if inv is None:
                    raise AuthError("Registration is by invitation only. Ask the administrator for an invitation code.")
                perms.update(inv.get("perms", {}))
            if self.count() >= MAX_USERS:
                raise AuthError("This server has reached its account limit")
            if not first:
                self.admin_id()  # fixes the owner before another account exists
            folder.mkdir(mode=0o700)
            fsutil.private(folder, 0o700)
            meta = folder / "meta.json"
            meta.write_text(json.dumps({"salt": base64.b64encode(salt).decode(), "verifier": base64.b64encode(verifier).decode(), "created": time.time(), "kdf": {k: SCRYPT[k] for k in ("n", "r", "p")}}))
            fsutil.private(meta, 0o600)
            if first:
                self._write_admin(uid)
            with self._store_lock():
                data = self.access()
                data["users"][uid] = {"perms": perms, "disabled": False, "limits": {}}
                self._write_access(data)
        acct = Account(uid, folder, key, email)
        acct.save("profile.bin", {"email": email, "created": int(time.time())})
        return acct

    def login(self, email: str, password: str) -> Account:
        email = _norm(email)
        uid = self.user_id(email)
        folder = self.root / uid
        try:
            meta = json.loads((folder / "meta.json").read_text())
            salt, want = base64.b64decode(meta["salt"]), base64.b64decode(meta["verifier"])
            kdf = _kdf_of(meta)
        except (OSError, ValueError, KeyError):
            _derive(password, b"\0" * 16)  # same cost for unknown emails, so timing does not reveal who is registered
            raise AuthError("Wrong email or password")
        verifier, key = _derive(password, salt, kdf)
        if not hmac.compare_digest(verifier, want):
            raise AuthError("Wrong email or password")
        if self.record(uid).get("disabled"):
            raise AuthError("This account is disabled. Ask the administrator.")
        return Account(uid, folder, key, email)

    def kdf_outdated(self, uid: str) -> bool:
        try:
            return _kdf_of(json.loads((self.root / uid / "meta.json").read_text())) != {k: SCRYPT[k] for k in ("n", "r", "p")}
        except (OSError, ValueError):
            return False

    def upgrade_kdf(self, acct: Account, password: str) -> Account:
        """Re-encrypt under the current scrypt cost with the same password (the file key comes from the KDF, so every file is rewritten)."""
        return self.change_password(acct, password, password)

    def change_password(self, acct: Account, old: str, new: str) -> Account:
        """Re-encrypt every file under a new salt and key. The old folder is kept as a backup until the switch is complete."""
        if not MIN_PASSWORD <= len(new) <= MAX_PASSWORD:
            raise AuthError(f"Password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters")
        acct = self.login(acct.email, old)  # proves the old password and gives a fresh key object
        salt = secrets.token_bytes(16)
        verifier, key = _derive(new, salt)
        fresh = Account(acct.id, acct.folder, key, acct.email)
        backup = acct.folder.with_name(acct.folder.name + ".bak")
        marker = acct.folder.with_name(acct.folder.name + ".rekeying")
        with self._store_lock(), filelock.locked(self.root / f".{acct.id}.lock"):  # no other process can write this account meanwhile
            data = {p.name: acct.load(p.name, None) for p in acct.folder.glob("*.bin")}
            shutil.rmtree(backup, ignore_errors=True)
            shutil.copytree(acct.folder, backup)
            created = self._created(acct.folder)  # keep the account's age, so who is next in line for administrator does not change
            marker.write_text("1")  # until this is removed, a restart rolls the account back to the backup
            try:
                for name, obj in data.items():
                    fresh.save(name, obj, rekey=True)
                tmp = acct.folder / f".meta.{secrets.token_hex(4)}.tmp"
                with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
                    fh.write(json.dumps({"salt": base64.b64encode(salt).decode(), "verifier": base64.b64encode(verifier).decode(), "created": created, "kdf": {k: SCRYPT[k] for k in ("n", "r", "p")}}))
                fsutil.replace(tmp, acct.folder / "meta.json")  # the commit point
            except Exception:
                shutil.rmtree(acct.folder, ignore_errors=True)
                fsutil.replace(backup, acct.folder)  # roll back
                marker.unlink(missing_ok=True)
                raise
            marker.unlink(missing_ok=True)
            shutil.rmtree(backup, ignore_errors=True)
        return fresh

    def delete(self, acct: Account, password: str) -> None:
        self.login(acct.email, password)
        shutil.rmtree(acct.folder)
        with self._store_lock():
            data = self.access()
            data["users"].pop(acct.id, None)
            self._write_access(data)

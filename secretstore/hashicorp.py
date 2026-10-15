# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Reading secrets out of HashiCorp Vault at run time.

A secret can hold a reference instead of a value: ``secret/data/app#password``
is the API path to read and the key in what comes back.  Both KV versions
work - version 2 answers with the data one level deeper, which is unwrapped.
Loona signs in with a token or AppRole set in Administration; one sign-in
serves a whole run.

The reference is what a person typed and Loona's own Vault identity does the
reading, so a reference may only point where its author may point:
superusers anywhere, everyone else under the allowed prefixes.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

REF_RE = re.compile(r"^(?P<path>[A-Za-z0-9_.\-/]+)#(?P<key>[^#]+)$")


class VaultError(Exception):
    pass


@dataclass
class Conf:
    address: str
    namespace: str = ""
    auth: str = "token"
    token: str = ""
    approle_mount: str = "approle"
    role_id: str = ""
    secret_id: str = ""
    verify_tls: bool = True
    ca_certificate: str = ""
    timeout: int = 10

    @classmethod
    def from_system(cls) -> "Conf | None":
        from administration import system

        row = system.get()
        if not row.hcv_address:
            return None
        return cls(
            address=row.hcv_address, namespace=row.hcv_namespace, auth=row.hcv_auth,
            token=row.hcv_token if row.hcv_auth == "token" else "",
            approle_mount=row.hcv_approle_mount, role_id=row.hcv_role_id,
            secret_id=row.hcv_secret_id if row.hcv_auth == "approle" else "",
            verify_tls=row.hcv_verify_tls, ca_certificate=row.hcv_ca_certificate, timeout=row.hcv_timeout,
        )


def parse(ref: str) -> tuple[str, str]:
    match = REF_RE.match((ref or "").strip())
    if not match:
        raise VaultError("Write it as path#key, e.g. secret/data/app#password.")
    path = match["path"].strip("/")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise VaultError("The path has an empty, . or .. part.")
    return path, match["key"]


PLACEHOLDERS = ("group", "project", "group_id", "project_id")


def allowed(ref: str, prefixes: str, **names: str) -> bool:
    """Whether ref lies under one of the prefixes, placeholders filled in.

    {group} and {project} are names, which a group's own admins can change;
    {group_id} and {project_id} cannot be steered that way.
    """
    try:
        path, _ = parse(ref)
    except VaultError:
        return False
    for line in (prefixes or "").splitlines():
        prefix = _fill(line.strip().strip("/"), names)
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            return True
    return False


def _fill(prefix: str, names: dict) -> str:
    """The prefix with its placeholders filled in; "" if one cannot be."""
    for placeholder in PLACEHOLDERS:
        token = "{" + placeholder + "}"
        if token in prefix:
            value = names.get(placeholder) or ""
            if not value or "/" in value or value in (".", ".."):
                return ""
            prefix = prefix.replace(token, value)
    return "" if "{" in prefix or "}" in prefix else prefix


class Client:
    def __init__(self, conf: Conf):
        self.conf = conf
        self._token = conf.token if conf.auth == "token" else ""
        self._read: dict[str, dict] = {}

    def _context(self):
        if not self.conf.address.startswith("https://"):
            return None
        if not self.conf.verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        return ssl.create_default_context(cadata=self.conf.ca_certificate or None)

    def _call(self, method, path, body=None, token=True) -> dict:
        headers = {"Accept": "application/json"}
        if token:
            headers["X-Vault-Token"] = self.token
        if self.conf.namespace:
            headers["X-Vault-Namespace"] = self.conf.namespace
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.conf.address.rstrip('/')}/v1/{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.conf.timeout, context=self._context()) as answer:
                return json.loads(answer.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                errors = "; ".join(json.loads(exc.read()).get("errors") or []) or exc.reason
            except ValueError:
                errors = exc.reason
            raise VaultError(f"Vault answered {exc.code} for {path}: {errors or 'no details'}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            raise VaultError(f"Could not reach Vault at {self.conf.address}: {reason}") from exc

    @property
    def token(self) -> str:
        if not self._token:
            if self.conf.auth != "approle":
                raise VaultError("No Vault token is set in Administration.")
            answer = self._call(
                "POST", f"auth/{self.conf.approle_mount.strip('/')}/login",
                {"role_id": self.conf.role_id, "secret_id": self.conf.secret_id}, token=False,
            )
            self._token = ((answer.get("auth") or {}).get("client_token")) or ""
            if not self._token:
                raise VaultError("AppRole sign-in gave no token.")
        return self._token

    def whoami(self) -> dict:
        """The token's own view of itself - for Test connection."""
        return self._call("GET", "auth/token/lookup-self").get("data") or {}

    def get(self, ref: str) -> str:
        path, key = parse(ref)
        if path not in self._read:
            data = self._call("GET", path).get("data")
            if not isinstance(data, dict):
                raise VaultError(f"Nothing at {path}.")
            # KV version 2 nests the secret under data, next to its metadata.
            if isinstance(data.get("data"), dict) and isinstance(data.get("metadata"), dict):
                data = data["data"]
            self._read[path] = data
        data = self._read[path]
        if key not in data:
            raise VaultError(f"{path} has no key {key!r}.")
        value = data[key]
        return value if isinstance(value, str) else json.dumps(value)

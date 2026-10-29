#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Custody of a person's Microsoft sign-in for on-behalf-of exchanges (C-1009 #6756 step 4)

The login callback keeps the token response in the session (``build_delegation``), reachable only with the session
cookie. A credential release happens with no cookie, so, when ``obo_custody_enabled`` is on, the same tokens are also
kept under the person's Entra subject (``c1009_obo_custody:<tid>:<oid>``, in the session Redis, for as long as the
session itself lives) — only for a Microsoft (Entra v2) sign-in whose access token, for the platform API
(``obo_api_client_id``), belongs to the very identity the ID token proved. Logout drops it and tells elitea_core to drop
the Graph tokens it minted for the person. ``auth_oidc_obo_assertion`` (rpc/obo_custody.py) hands out the access token, refreshing
it once with the stored refresh token when asked or when it is about to expire.

Nothing here logs a token or a token response; only fixed reasons and exception types.
"""

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import time
from urllib.parse import urlsplit

import requests  # pylint: disable=E0401

from pylon.core.tools import log, web  # pylint: disable=E0611,E0401

CUSTODY_TTL_S = 86400              # only when the session lifetime cannot be read
AUTHORITY_HOST = "login.microsoftonline.com"
DROPPED_EVENT = "auth_oidc_obo_custody_dropped"   # elitea_core drops the person's cached Graph tokens on it
DEFAULT_PREFIX = "c1009_obo_custody:"
REFRESH_BEFORE_S = 120             # refresh an access token with less life than this left
HTTP_TIMEOUT_S = 4                 # inside elitea_core's 5 s RPC wait
DEFAULT_REQUEST_KEY_ENV = "ELITEA_OBO_CUSTODY_KEY"   # shared with elitea_core only
MIN_REQUEST_KEY_CHARS = 32
REQUEST_MAX_AGE_S = 30
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
MAX_TOKEN_CHARS = 16_384
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ENTRA_V2 = "https://login.microsoftonline.com/{tid}/v2.0"
_ENTRA_V1 = "https://sts.windows.net/{tid}/"   # an API whose manifest still asks for v1 access tokens


def _claims(token):
    """The payload of a JWT, read for its structure (the token came from the token endpoint over TLS)."""
    if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_CHARS or token.count(".") != 2:
        return None
    body = token.split(".")[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


def entra_token_of(token, tid, oid, audience) -> bool:
    """Is ``token`` an Entra-issued access token of exactly this person, for the platform API ``audience``?"""
    claims = _claims(token)
    return claims is not None and bool(audience) and \
        claims.get("iss") in (_ENTRA_V2.format(tid=tid), _ENTRA_V1.format(tid=tid)) and \
        claims.get("tid") == tid and claims.get("oid") == oid and claims.get("aud") in (audience, f"api://{audience}")


class Method:  # pylint: disable=E1101,R0903
    """ Methods """

    @web.method()
    def obo_request_signed(self, store, tid, oid, refresh, iat, nonce, signature):
        """ Did elitea_core ask (the request key is shared with it only), recently, and only once? A worker that merely
        reaches the RPC bus cannot ask for anyone's assertion. (The answer to elitea_core's own request crosses the bus
        like the token the identity verifier reads at every admission.) The nonce is spent in the session Redis. """
        key = self.obo_request_key()
        if not key or not isinstance(signature, str) or not isinstance(nonce, str) \
                or not _NONCE.match(nonce) or isinstance(iat, bool) or not isinstance(iat, int) \
                or abs(time.time() - iat) > REQUEST_MAX_AGE_S:
            return False
        message = "|".join(("v1", tid, oid, "1" if refresh else "0", str(iat), nonce)).encode("utf-8")
        expected = hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return False
        prefix = self.obo_custody_key(tid, oid)
        return bool(store.set(f"{prefix}:nonce:{nonce}", "1", nx=True, ex=2 * REQUEST_MAX_AGE_S))

    @web.method()
    def obo_request_key(self):
        """ The request key shared with elitea_core, or "" when it is missing or too short """
        key = os.environ.get(self.descriptor.config.get("obo_custody_key_env") or DEFAULT_REQUEST_KEY_ENV) or ""
        return key if len(key) >= MIN_REQUEST_KEY_CHARS else ""

    @web.method()
    def check_obo_custody_config(self):
        """ At init: custody switched on needs the request key and the platform API's client id; without them nothing
        is kept (an ERROR says why). True when custody is off or fully configured. """
        if not self.descriptor.config.get("obo_custody_enabled", False):
            return True
        missing = [name for name, value in (("the request key", self.obo_request_key()),
                                            ("obo_api_client_id", self.descriptor.config.get("obo_api_client_id")))
                   if not value]
        if missing:
            log.error("OBO custody is enabled but %s is missing: no Microsoft sign-in is kept", " and ".join(missing))
            return False
        return True

    @web.method()
    def obo_custody_store(self):
        """ The session Redis when custody is switched on and configured (``check_obo_custody_config``), else None:
        a custody nobody could ask for is never kept """
        if not self.descriptor.config.get("obo_custody_enabled", False) or not self.obo_request_key() or \
                not self.descriptor.config.get("obo_api_client_id"):
            return None
        interface = getattr(getattr(self.context, "app", None), "session_interface", None)
        return getattr(interface, "client", None)

    @web.method()
    def obo_custody_ttl(self):
        """ How long custody lives: as long as a session does (the person is signed in), the run cap otherwise. Read
        from the app config pylon sets from ``COOKIES_LIFETIME`` (seconds or a timedelta); pylon's app shim proxies
        ``config`` and raises for attributes it does not know, so nothing else is asked of it. """
        try:
            lifetime = self.context.app.config.get("PERMANENT_SESSION_LIFETIME")
        except Exception:  # pylint: disable=W0703
            lifetime = None
        try:
            seconds = lifetime.total_seconds() if hasattr(lifetime, "total_seconds") else float(lifetime)
        except (TypeError, ValueError):
            seconds = None
        return max(60, int(seconds)) if seconds and seconds > 0 else CUSTODY_TTL_S

    @web.method()
    def obo_custody_key(self, tid, oid):
        """ The Redis key of a person's custody; None for ids that cannot be one """
        if not (isinstance(tid, str) and _ID.match(tid) and isinstance(oid, str) and _ID.match(oid)):
            return None
        # a namespace of its own: never one a session id could name, whether sessions are signed or not
        return f"{self.descriptor.config.get('obo_custody_prefix') or DEFAULT_PREFIX}{tid}:{oid}"

    @web.method()
    def keep_obo_custody(self, identity, delegation):
        """ Keep the sign-in under the person's subject (login callback). Best effort: a failure is logged, the login
        goes on. A sign-in that is not Microsoft's own for this identity is not kept. """
        try:
            store = self.obo_custody_store()
            if store is None or not isinstance(identity, dict) or not isinstance(delegation, dict):
                return False
            tid, oid = identity.get("tid"), identity.get("oid")
            key = self.obo_custody_key(tid, oid)
            if key is None or identity.get("issuer") != _ENTRA_V2.format(tid=tid) or not entra_token_of(
                    delegation.get("access_token"), tid, oid, self.descriptor.config.get("obo_api_client_id")):
                return False
            record = {
                "issuer": identity["issuer"], "tid": tid, "oid": oid, "assertion_source": "login",
                "access_token": delegation["access_token"], "refresh_token": delegation.get("refresh_token"),
                "expires_at": delegation.get("expires_at"),
            }
            store.set(key, json.dumps(record), ex=self.obo_custody_ttl())
            return True
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO custody was not kept: %s", type(exception).__name__)
            return False

    @web.method()
    def drop_obo_custody(self, identity):
        """ Forget the person's sign-in (logout), and tell elitea_core to drop the Graph tokens it minted for them.
        Best effort. """
        try:
            store = self.obo_custody_store()
            key = self.obo_custody_key(identity.get("tid"), identity.get("oid")) if isinstance(identity, dict) else None
            if store is None or key is None:
                return
            store.delete(key)
            self.context.event_manager.fire_event(DROPPED_EVENT, {"tid": identity["tid"], "oid": identity["oid"]})
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO custody was not dropped: %s", type(exception).__name__)

    @web.method()
    def refresh_obo_custody(self, record):
        """ A new access token for the record, with its refresh token and this plugin's login client, through a
        hardened request (https, the configured token endpoint's host only, no redirect, no proxy from the
        environment, a timeout). The updated record, or None. """
        refresh_token = record.get("refresh_token")
        endpoint = self.descriptor.config.get("token_endpoint")
        parts = urlsplit(endpoint or "")
        if not refresh_token or parts.scheme != "https" or parts.hostname != AUTHORITY_HOST or \
                parts.port not in (None, 443):
            return None   # custody is Entra-only, so its refresh goes to the Entra authority only
        config = self.descriptor.config
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                "scope": config.get("scope", config.get("target_scope", "openid profile email"))}
        auth = None
        if config.get("token_endpoint_auth", "basic") == "basic":
            auth = (config["client_id"], config["client_secret"])
        else:
            data.update(client_id=config["client_id"], client_secret=config["client_secret"])
        session = requests.Session()
        session.trust_env = False
        session.max_redirects = 0
        session.proxies = {}
        try:
            with session:
                response = session.post(endpoint, data=data, auth=auth, timeout=HTTP_TIMEOUT_S, allow_redirects=False,
                                        verify=True)
            body = response.json() if response.status_code == 200 else None
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO custody refresh failed: %s", type(exception).__name__)
            return None
        if not isinstance(body, dict) or not entra_token_of(body.get("access_token"), record["tid"], record["oid"],
                                                            config.get("obo_api_client_id")):
            log.warning("OBO custody refresh was refused (status %s)", getattr(response, "status_code", None))
            return None
        try:
            expires_at = int(time.time()) + int(body.get("expires_in"))
        except (TypeError, ValueError):
            expires_at = None
        return {**record, "access_token": body["access_token"],
                "refresh_token": body.get("refresh_token") or refresh_token, "expires_at": expires_at}

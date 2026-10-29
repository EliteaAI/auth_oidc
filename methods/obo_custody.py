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

Step 4b (``obo_assertion_source: keycloak_broker``): the login is Keycloak's, which brokered it to Entra and stored
Entra's token response. Right after the login, one call to the realm's broker token endpoint
(``<realm>/broker/<obo_broker_alias>/token`` on the host of the realm's token endpoint, with the session's Keycloak
access token) fetches it; the same record is kept with ``assertion_source: "broker"`` only for an unexpired Entra v2
access token for the platform API of exactly the identity Keycloak vouched for. Its refresh goes to the Entra authority
with the Entra client Keycloak brokers through (``obo_broker_refresh_*``), never to Keycloak. When Keycloak says the
login has no readable brokered sign-in (400/403/404), an earlier record of the person is dropped too.

Nothing here logs a token or a token response; only fixed reasons, status codes and exception types.
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
CONNECT_TIMEOUT_S = 3
BROKER_TOTAL_S = 8                 # the broker call at login (checked between reads; one read waits at most 4 s)
MAX_TOKEN_RESPONSE_BYTES = 65_536  # a token response is a few KiB (the broker's and the refresh's)
KEYCLOAK_TOKEN_PATH = "/protocol/openid-connect/token"
SOURCES = ("login", "keycloak_broker")
_ALIAS = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
BROKER_REFUSALS = {   # what Keycloak's broker token endpoint means by its answer (status codes only are logged)
    400: "the login is not brokered, Store tokens is off, or the session token was refused",
    403: "the person lacks the broker read-token role",
    404: "no token is stored for the person's brokered login",
}
DROP_STATUSES = frozenset(BROKER_REFUSALS)   # Keycloak's own "no readable brokered sign-in": earlier custody goes too
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


def broker_token_of(token, tid, oid, audience) -> bool:
    """Is ``token`` (from Keycloak's broker endpoint) an Entra v2 access token of exactly this person, issued for the
    platform API ``audience`` itself? Stricter than ``entra_token_of``: v2 only, the client id as audience."""
    claims = _claims(token)
    return claims is not None and bool(audience) and claims.get("ver") == "2.0" and \
        claims.get("iss") == _ENTRA_V2.format(tid=tid) and claims.get("tid") == tid and claims.get("oid") == oid and \
        claims.get("aud") == audience


def _hardened_session():
    """requests.Session that ignores proxy settings from the environment and follows no redirect."""
    session = requests.Session()
    session.trust_env = False
    session.max_redirects = 0
    session.proxies = {}
    return session


def _read_bounded(response, limit, deadline):
    """The body, or None when it is larger than ``limit`` bytes or arrives after ``deadline`` (monotonic)."""
    chunks, size = [], 0
    for chunk in response.iter_content(chunk_size=1024):
        size += len(chunk)
        if size > limit or time.monotonic() > deadline:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


class Method:  # pylint: disable=E1101,R0903
    """ Methods """

    @web.method()
    def obo_request_signed(self, store, tid, oid, refresh, iat, nonce, signature):
        """ Did elitea_core ask (the request key is shared with it only), recently, and only once? A worker that merely
        reaches the RPC bus cannot ask for anyone's assertion. (The answer to elitea_core's own request crosses the bus
        like the token the identity verifier reads at every admission.) The nonce is spent in the session Redis. """
        return self.obo_signed(store, tid, oid, ("v1", tid, oid, "1" if refresh else "0"), iat, nonce, signature)

    @web.method()
    def obo_signed(self, store, tid, oid, fields, iat, nonce, signature):  # pylint: disable=R0913
        """ The check of every signed request: HMAC-SHA256 with the shared request key over ``fields`` (a version tag
        first, so a request of one kind never verifies as another), then ``iat`` and ``nonce``; recent, and the nonce
        spent once under the person's key prefix. """
        key = self.obo_request_key()
        if not key or not isinstance(signature, str) or not isinstance(nonce, str) \
                or not _NONCE.match(nonce) or isinstance(iat, bool) or not isinstance(iat, int) \
                or abs(time.time() - iat) > REQUEST_MAX_AGE_S:
            return False
        message = "|".join((*fields, str(iat), nonce)).encode("utf-8")
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
    def obo_assertion_source(self):
        """ Where the Microsoft sign-in comes from: "login" (default: the login is Entra's own) or "keycloak_broker"
        (Keycloak brokered it to Entra); None for any other value """
        source = self.descriptor.config.get("obo_assertion_source") or "login"
        return source if source in SOURCES else None

    @web.method()
    def obo_broker_url(self):
        """ The realm's broker token endpoint for ``obo_broker_alias``: on the host this plugin already reaches the
        realm's token endpoint at (configured, or from discovery; it may differ from the issuer's browser-facing host),
        for the same realm path as the configured issuer. None when it cannot be built safely (https only; http only for
        localhost names with obo_broker_insecure_dev_http) """
        config = self.descriptor.config
        issuer, alias, endpoint = config.get("issuer"), config.get("obo_broker_alias"), config.get("token_endpoint")
        if not all(isinstance(value, str) for value in (issuer, alias, endpoint)) or not _ALIAS.match(alias) or \
                not endpoint.endswith(KEYCLOAK_TOKEN_PATH):
            return None
        base = endpoint[:-len(KEYCLOAK_TOKEN_PATH)]
        parts = urlsplit(base)
        host = parts.hostname or ""
        local = host == "localhost" or host.endswith(".localhost")
        if parts.scheme != "https" and not (
                parts.scheme == "http" and local and config.get("obo_broker_insecure_dev_http") is True):
            return None
        if not host or parts.username or parts.password or parts.query or parts.fragment or not parts.path or \
                parts.path.rstrip("/") != urlsplit(issuer).path.rstrip("/"):
            return None   # the token endpoint must be the issuer's own realm
        return f"{base}/broker/{alias}/token"

    @web.method()
    def obo_custody_problems(self):
        """ What custody switched on still needs: [] when it is fully configured """
        config = self.descriptor.config
        problems = [name for name, value in (("the request key", self.obo_request_key()),
                                             ("obo_api_client_id", config.get("obo_api_client_id"))) if not value]
        source = self.obo_assertion_source()
        if source is None:
            problems.append("a known obo_assertion_source (login or keycloak_broker)")
        elif source == "keycloak_broker" and self.obo_broker_url() is None:
            problems.append("a broker token endpoint (the realm's https token endpoint and a valid obo_broker_alias)")
        return problems

    @web.method()
    def check_obo_custody_config(self):
        """ At init: custody switched on needs the request key and the platform API's client id (and, brokered, the
        broker endpoint); without them nothing is kept (an ERROR says why). True when custody is off or fully
        configured. """
        if not self.descriptor.config.get("obo_custody_enabled", False):
            return True
        missing = self.obo_custody_problems()
        if missing:
            log.error("OBO custody is enabled but %s is missing: no Microsoft sign-in is kept", " and ".join(missing))
            return False
        if self.obo_assertion_source() == "keycloak_broker" and self.obo_broker_refresh_client() is None:
            log.warning("OBO custody (brokered) has no refresh client: a sign-in serves runs until its Microsoft "
                        "token expires, then the person signs in again")
        return True

    @web.method()
    def obo_custody_store(self):
        """ The session Redis when custody is switched on and configured (``check_obo_custody_config``), else None:
        a custody nobody could ask for is never kept """
        if not self.descriptor.config.get("obo_custody_enabled", False) or self.obo_custody_problems():
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
            if self.obo_assertion_source() == "keycloak_broker":
                return self.keep_brokered_custody(store, key, identity, delegation)
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
    def keep_brokered_custody(self, store, key, identity, delegation):
        """ Keycloak brokered the login: fetch Entra's token response from the realm with the session's Keycloak
        access token and keep it, as the login source keeps its own, when it is the very person's v2 token for the
        platform API. Otherwise nothing is kept and one WARNING (no claim, no token) says why. """
        if key is None:
            log.warning("OBO custody was not kept: the realm's token carries no Entra identity (a realm user who did "
                        "not sign in through the Microsoft broker)")
            return False
        if identity.get("issuer") != self.descriptor.config.get("issuer"):
            log.warning("OBO custody was not kept: the login is not one of the configured realm")
            return False
        tid, oid = identity["tid"], identity["oid"]
        status, body = self.fetch_broker_token(delegation.get("access_token"))
        if status in DROP_STATUSES:
            self.drop_obo_custody(identity)   # Keycloak no longer lends this person's sign-in: an earlier one goes too
            return False
        if body is None:
            return False
        access_token = body.get("access_token")
        if not broker_token_of(access_token, tid, oid, self.descriptor.config.get("obo_api_client_id")):
            log.warning("OBO custody was not kept: the brokered Microsoft token is not a v2 token of this person "
                        "for the platform API")
            return False
        expires_at = _claims(access_token).get("exp")
        refresh_token = body.get("refresh_token")
        record = {
            "issuer": identity["issuer"], "tid": tid, "oid": oid, "assertion_source": "broker",
            "access_token": access_token,
            "refresh_token": refresh_token if isinstance(refresh_token, str) and
            0 < len(refresh_token) <= MAX_TOKEN_CHARS else None,
            "expires_at": expires_at if isinstance(expires_at, int) and not isinstance(expires_at, bool) else None,
        }
        if record["expires_at"] is None or record["expires_at"] - time.time() < REFRESH_BEFORE_S:
            # Keycloak hands back what it stored at the last brokered login (an SSO login reuses it): renew it at
            # Entra when the refresh client is configured, else keep nothing
            renewed = self.refresh_obo_custody(record) if self.obo_broker_refresh_client() is not None else None
            if renewed is None:
                log.warning("OBO custody was not kept: the brokered Microsoft token has expired and %s",
                            "could not be renewed" if self.obo_broker_refresh_client() else
                            "no refresh client is configured")
                return False
            record = renewed
            log.info("OBO custody: the brokered Microsoft token had expired and was renewed")
        store.set(key, json.dumps(record), ex=self.obo_custody_ttl())
        return True

    @web.method()
    def fetch_broker_token(self, access_token):
        """ Keycloak's stored Entra token response for the session's person: one GET to the broker token endpoint,
        bearer = the session's Keycloak access token, no body; hardened (the issuer's host only, no redirect, no proxy
        from the environment, TLS verified, a connect/read timeout, at most BROKER_TOTAL_S and MAX_BROKER_BYTES).
        ``(status, parsed token response)``; the response is None after one WARNING (status None: no answer). The
        answer is never logged. """
        url = self.obo_broker_url()
        if url is None or not isinstance(access_token, str) or not 0 < len(access_token) <= MAX_TOKEN_CHARS:
            log.warning("OBO custody was not kept: no broker endpoint or session token to fetch the Microsoft "
                        "sign-in with")
            return None, None
        deadline = time.monotonic() + BROKER_TOTAL_S
        try:
            with _hardened_session() as session:
                response = session.get(url, headers={"Authorization": f"Bearer {access_token}",
                                                     "Accept": "application/json", "Accept-Encoding": "identity"},
                                       timeout=(CONNECT_TIMEOUT_S, HTTP_TIMEOUT_S), allow_redirects=False,
                                       verify=True, stream=True)
                with response:
                    status = response.status_code
                    raw = _read_bounded(response, MAX_TOKEN_RESPONSE_BYTES, deadline) if status == 200 else None
        except Exception as exception:  # pylint: disable=W0703
            log.warning("OBO custody was not kept: the broker token endpoint failed (%s)", type(exception).__name__)
            return None, None
        if status != 200:
            log.warning("OBO custody was not kept: the broker token endpoint answered %s (%s)%s", status,
                        BROKER_REFUSALS.get(status, "unexpected answer"),
                        "; an earlier sign-in of the person is dropped" if status in DROP_STATUSES else "")
            return status, None
        try:
            body = json.loads(raw) if raw is not None else None
        except ValueError:
            body = None
        if not isinstance(body, dict):
            log.warning("OBO custody was not kept: the broker token endpoint answered no token response (too large, "
                        "too slow or not JSON)")
            return status, None
        return status, body

    @web.method()
    def obo_broker_refresh_client(self):
        """ (client id, client secret, scope) of the Entra client Keycloak brokers through, for refreshing a brokered
        record at the Entra authority; None unless all three are configured (the secret from the environment
        variable named by obo_broker_refresh_client_secret_env) """
        config = self.descriptor.config
        name = config.get("obo_broker_refresh_client_secret_env")
        secret = os.environ.get(name) if isinstance(name, str) and name else None
        found = (config.get("obo_broker_refresh_client_id"), secret, config.get("obo_broker_refresh_scope"))
        return found if all(isinstance(value, str) and value for value in found) else None

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
        hardened request (https, the configured token endpoint's host only — for a brokered record the Entra
        authority of its tenant with the obo_broker_refresh client —, no redirect, no proxy from the environment, a
        timeout). The updated record, or None. """
        return self.refresh_obo_record(record)[0]

    @web.method()
    def refresh_obo_record(self, record):  # pylint: disable=R0914
        """ ``refresh_obo_custody`` that also says why it failed: ``(updated record, False)``, ``(None, True)`` when
        the authority refused the refresh token itself (``invalid_grant``: expired, revoked or consent withdrawn at
        Microsoft — a definitive answer), ``(None, False)`` for anything else (not configured, unreachable, a
        malformed or foreign answer: it may work later). """
        refresh_token = record.get("refresh_token")
        config = self.descriptor.config
        if record.get("assertion_source") == "broker":
            # the record came through Keycloak; its refresh token is Entra's, for the client Keycloak brokers through
            client, tid = self.obo_broker_refresh_client(), record.get("tid")
            if not refresh_token or client is None or not isinstance(tid, str) or not _GUID.match(tid):
                return None, False
            endpoint, auth, valid = f"https://{AUTHORITY_HOST}/{tid}/oauth2/v2.0/token", None, broker_token_of
            data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "scope": client[2],
                    "client_id": client[0], "client_secret": client[1]}
        else:
            endpoint, valid = config.get("token_endpoint"), entra_token_of
            parts = urlsplit(endpoint or "")
            if not refresh_token or parts.scheme != "https" or parts.hostname != AUTHORITY_HOST or \
                    parts.port not in (None, 443):
                return None, False   # custody is Entra-only, so its refresh goes to the Entra authority only
            data = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                    "scope": config.get("scope", config.get("target_scope", "openid profile email"))}
            auth = None
            if config.get("token_endpoint_auth", "basic") == "basic":
                auth = (config["client_id"], config["client_secret"])
            else:
                data.update(client_id=config["client_id"], client_secret=config["client_secret"])
        deadline, status, raw = time.monotonic() + HTTP_TIMEOUT_S, None, None
        try:
            with _hardened_session() as session:
                response = session.post(endpoint, data=data, auth=auth, timeout=HTTP_TIMEOUT_S, allow_redirects=False,
                                        verify=True, stream=True)
                with response:
                    status = response.status_code
                    raw = _read_bounded(response, MAX_TOKEN_RESPONSE_BYTES, deadline) if status in (200, 400) \
                        else None
            body = json.loads(raw) if raw is not None else None
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO custody refresh failed: %s", type(exception).__name__)
            return None, False
        if status != 200 or not isinstance(body, dict) or not valid(
                body.get("access_token"), record["tid"], record["oid"], config.get("obo_api_client_id")):
            refused = status == 400 and isinstance(body, dict) and body.get("error") == "invalid_grant"
            log.warning("OBO custody refresh was refused (status %s%s)", status, ", invalid_grant" if refused else "")
            return None, refused
        try:
            expires_at = int(time.time()) + int(body.get("expires_in"))
        except (TypeError, ValueError):
            expires_at = None
        return {**record, "access_token": body["access_token"],
                "refresh_token": body.get("refresh_token") or refresh_token, "expires_at": expires_at}, False

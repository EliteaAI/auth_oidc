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

""" RPC: the assertion of an on-behalf-of exchange (C-1009 #6756 step 4), and the offline consent of a mandate owner
(#7131): a refresh token handed out once, at the owner's consent, and redeemed for the run's assertion later """

import hashlib
import json
import re
import time

from pylon.core.tools import log, web  # pylint: disable=E0611,E0401

from ..methods.obo_custody import (
    MAX_SEALED_CHARS, MAX_TOKEN_CHARS, REFRESH_BEFORE_S, entra_token_of, open_sealed, seal, seal_aad, seal_key,
)

UNAVAILABLE = {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
REFUSED = {"ok": False, "code": "REQUEST_REFUSED"}
# what an offline grant is bound to: one autonomous mandate (elitea_core's ``mandate:<uuid>``)
HOLDER = re.compile(r"^mandate:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
OFFLINE_SOURCES = ("login", "broker")   # the custody record's own ``assertion_source``: which client redeems it


def token_digest(token) -> str:
    """ What a signature covers instead of the sealed refresh token itself """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_oidc_obo_assertion", "obo_assertion")
    def obo_assertion(self, tid, oid, refresh=False, iat=None, nonce=None, signature=None):  # pylint: disable=R0913
        """ The Entra access token of the person ``(tid, oid)``, for elitea_core's credential release to exchange:
        ``{"ok": True, "assertion", "expires_at", "custody_expires_at"}``, or ``{"ok": False, "code":
        "ASSERTION_UNAVAILABLE"}`` when no
        Microsoft sign-in of theirs is kept (signed out, expired, a login that is neither Entra's nor brokered to it,
        custody off) or it cannot be renewed. ``refresh``: renew it first with the stored refresh token (an exchange
        refused it as expired).
        ``iat``, ``nonce``, ``signature``: elitea_core's signature over the request (``obo_request_signed``); without
        a good one the answer is ``REQUEST_REFUSED``. ``custody_expires_at``: when the custody itself ends (epoch
        seconds; its lifetime is fixed at the sign-in), so elitea_core keeps no token it minted from it past that
        (#7281). Never raises; never logs a token. """
        try:
            store = self.obo_custody_store()
            key = self.obo_custody_key(tid, oid)
            if store is None or key is None:
                return dict(UNAVAILABLE)
            if not self.obo_request_signed(store, tid, oid, bool(refresh), iat, nonce, signature):
                log.warning("OBO assertion request refused")
                return {"ok": False, "code": "REQUEST_REFUSED"}
            pipe = store.pipeline(transaction=True)   # the record and its remaining lifetime, read together
            pipe.get(key)
            pipe.ttl(key)
            raw, ttl = pipe.execute()
            record = json.loads(raw) if raw else None
            if not isinstance(record, dict) or (record.get("tid"), record.get("oid")) != (tid, oid) or \
                    not entra_token_of(record.get("access_token"), tid, oid,
                                       self.descriptor.config.get("obo_api_client_id")):
                return dict(UNAVAILABLE)
            expires_at = record.get("expires_at")
            if refresh or not isinstance(expires_at, int) or expires_at - time.time() < REFRESH_BEFORE_S:
                record = self.refresh_obo_custody(record)
                if record is None:
                    return dict(UNAVAILABLE)
                # the custody's own lifetime is not extended, and a custody that ended meanwhile is not brought back
                if not store.set(key, json.dumps(record), keepttl=True, xx=True):
                    return dict(UNAVAILABLE)
                log.info("OBO custody refreshed")
            if not isinstance(ttl, int) or ttl == -2 or ttl == 0:
                return dict(UNAVAILABLE)   # it ended between the reads
            # a custody with no lifetime (never written so) is treated as ending now: Main keeps nothing minted from it
            ends = int(time.time()) + (ttl if ttl > 0 else 0)
            return {"ok": True, "assertion": record["access_token"], "expires_at": record.get("expires_at"),
                    "custody_expires_at": ends}
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO assertion failed: %s", type(exception).__name__)
            return dict(UNAVAILABLE)

    @web.rpc("auth_oidc_obo_offline_grant", "obo_offline_grant")
    def obo_offline_grant(self, tid, oid, holder, iat=None, nonce=None, signature=None):  # pylint: disable=R0913
        """ The mandate owner consents (#7131): from the custody of their current Microsoft sign-in, one refresh of
        the stored refresh token, whose new refresh token is handed to elitea_core to keep as the owner's offline
        material for ``holder`` (``mandate:<uuid>``). ``{"ok": True, "sealed_refresh_token", "assertion_source"}``:
        the token sealed (AES-256-GCM, a subkey of the request key, bound to ``grant-reply`` and this request), never in
        plain text on the bus; or ``{"ok": False, "code": ASSERTION_UNAVAILABLE | REQUEST_REFUSED}`` (no kept sign-in or
        no refresh token in it, the refresh refused; a request elitea_core did not sign over
        ``v1-offline-grant|tid|oid|holder``). The custody itself is left as it is. Never raises; never logs a token. """
        try:
            store = self.obo_custody_store()
            key = self.obo_custody_key(tid, oid)
            if store is None or key is None:
                return dict(UNAVAILABLE)
            if not isinstance(holder, str) or not HOLDER.match(holder) or not self.obo_signed(
                    store, tid, oid, ("v1-offline-grant", tid, oid, holder), iat, nonce, signature):
                log.warning("OBO offline grant request refused")
                return dict(REFUSED)
            raw = store.get(key)
            record = json.loads(raw) if raw else None
            if not isinstance(record, dict) or (record.get("tid"), record.get("oid")) != (tid, oid) or \
                    record.get("assertion_source") not in OFFLINE_SOURCES or not record.get("refresh_token"):
                return dict(UNAVAILABLE)
            renewed, _ = self.refresh_obo_record(record)
            if renewed is None or not isinstance(renewed.get("refresh_token"), str) or \
                    not 0 < len(renewed["refresh_token"]) <= MAX_TOKEN_CHARS:
                return dict(UNAVAILABLE)
            sealed = seal(seal_key(self.obo_request_key()), renewed["refresh_token"],
                          seal_aad("grant-reply", tid, oid, holder, nonce))
            log.info("OBO offline grant issued")
            return {"ok": True, "sealed_refresh_token": sealed, "assertion_source": record["assertion_source"]}
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO offline grant failed: %s", type(exception).__name__)
            return dict(UNAVAILABLE)

    @web.rpc("auth_oidc_obo_offline_assertion", "obo_offline_assertion")
    def obo_offline_assertion(  # pylint: disable=R0913
            self, tid, oid, holder, source, sealed_refresh_token, iat=None, nonce=None, signature=None):
        """ The assertion of a mandate run (#7131): the owner's offline refresh token (``obo_offline_grant``), sealed by
        elitea_core for this request (``redeem-req``), redeemed with the client of its ``source`` for an Entra access
        token of exactly ``(tid, oid)`` for the platform API. ``{"ok": True, "assertion", "expires_at",
        "sealed_refresh_token"}`` (the rotated token sealed for ``redeem-reply``, or None when the authority issued
        none), or ``{"ok": False, "code"}``: ``CONSENT_REFUSED`` when the authority refused the refresh token itself
        (expired, revoked, consent withdrawn at Microsoft: definitive), ``ASSERTION_UNAVAILABLE`` for anything that may
        work later, ``REQUEST_REFUSED`` for a request elitea_core did not sign (over
        ``v1-offline|tid|oid|holder|source|sha256(sealed token)``) or a token that does not open. Nothing is kept
        here. Never raises; never logs a token. """
        try:
            store = self.obo_custody_store()
            if store is None or self.obo_custody_key(tid, oid) is None:
                return dict(UNAVAILABLE)
            if not isinstance(holder, str) or not HOLDER.match(holder) or source not in OFFLINE_SOURCES or \
                    not isinstance(sealed_refresh_token, str) or not 0 < len(sealed_refresh_token) <= MAX_SEALED_CHARS \
                    or not self.obo_signed(store, tid, oid, ("v1-offline", tid, oid, holder, source,
                                                             token_digest(sealed_refresh_token)), iat, nonce, signature):
                log.warning("OBO offline assertion request refused")
                return dict(REFUSED)
            key = seal_key(self.obo_request_key())
            refresh_token = open_sealed(key, sealed_refresh_token, seal_aad("redeem-req", tid, oid, holder, nonce))
            if refresh_token is None or not 0 < len(refresh_token) <= MAX_TOKEN_CHARS:
                log.warning("OBO offline assertion request refused (the token does not open)")
                return dict(REFUSED)
            renewed, refused = self.refresh_obo_record(
                {"tid": tid, "oid": oid, "assertion_source": source, "refresh_token": refresh_token})
            if renewed is None:
                return {"ok": False, "code": "CONSENT_REFUSED"} if refused else dict(UNAVAILABLE)
            rotated = renewed.get("refresh_token")
            return {"ok": True, "assertion": renewed["access_token"], "expires_at": renewed.get("expires_at"),
                    "sealed_refresh_token": seal(key, rotated, seal_aad("redeem-reply", tid, oid, holder, nonce))
                    if isinstance(rotated, str) and rotated and rotated != refresh_token else None}
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO offline assertion failed: %s", type(exception).__name__)
            return dict(UNAVAILABLE)

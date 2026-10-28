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

""" RPC: the assertion of an on-behalf-of exchange (C-1009 #6756 step 4) """

import json
import time

from pylon.core.tools import log, web  # pylint: disable=E0611,E0401

from ..methods.obo_custody import REFRESH_BEFORE_S, entra_token_of

UNAVAILABLE = {"ok": False, "code": "ASSERTION_UNAVAILABLE"}


class RPC:  # pylint: disable=R0903,E1101

    @web.rpc("auth_oidc_obo_assertion", "obo_assertion")
    def obo_assertion(self, tid, oid, refresh=False, iat=None, nonce=None, signature=None):  # pylint: disable=R0913
        """ The Entra access token of the person ``(tid, oid)``, for elitea_core's credential release to exchange:
        ``{"ok": True, "assertion", "expires_at"}``, or ``{"ok": False, "code": "ASSERTION_UNAVAILABLE"}`` when no
        Microsoft sign-in of theirs is kept (signed out, expired, a Keycloak login, custody off) or it cannot be
        renewed. ``refresh``: renew it first with the stored refresh token (an exchange refused it as expired).
        ``iat``, ``nonce``, ``signature``: elitea_core's signature over the request (``obo_request_signed``); without
        a good one the answer is ``REQUEST_REFUSED``. Never raises; never logs a token. """
        try:
            store = self.obo_custody_store()
            key = self.obo_custody_key(tid, oid)
            if store is None or key is None:
                return dict(UNAVAILABLE)
            if not self.obo_request_signed(store, tid, oid, bool(refresh), iat, nonce, signature):
                log.warning("OBO assertion request refused")
                return {"ok": False, "code": "REQUEST_REFUSED"}
            raw = store.get(key)
            record = json.loads(raw) if raw else None
            if not isinstance(record, dict) or (record.get("tid"), record.get("oid")) != (tid, oid) or \
                    not entra_token_of(record.get("access_token"), tid, oid):
                return dict(UNAVAILABLE)
            expires_at = record.get("expires_at")
            if refresh or not isinstance(expires_at, int) or expires_at - time.time() < REFRESH_BEFORE_S:
                record = self.refresh_obo_custody(record)
                if record is None:
                    return dict(UNAVAILABLE)
                store.set(key, json.dumps(record), keepttl=True)   # the custody's own lifetime is not extended
                log.info("OBO custody refreshed")
            return {"ok": True, "assertion": record["access_token"], "expires_at": record.get("expires_at")}
        except Exception as exception:  # pylint: disable=W0703
            log.error("OBO assertion failed: %s", type(exception).__name__)
            return dict(UNAVAILABLE)

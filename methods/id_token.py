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

""" Method """

import hmac
import time

import requests  # pylint: disable=E0401
import jwt  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401

ALGORITHMS = ["RS256", "RS384", "RS512", "ES256"]
DEFAULT_LEEWAY = 60
JWKS_LIFESPAN = 3600
DISCOVERY_PATH = "/.well-known/openid-configuration"
# iss is required by PyJWT whenever an issuer is configured; without one the token
# is still accepted as before.
REQUIRED_CLAIMS = ["exp", "iat", "sub", "aud"]


def nonce_matches(expected, actual):
    """ Constant-time nonce comparison; False unless both are non-empty strings """
    if not isinstance(expected, str) or not isinstance(actual, str):
        return False
    if not expected or not actual:
        return False
    return hmac.compare_digest(expected.encode(), actual.encode())


def _is_true(value):
    """ An explicit opt-in: YAML true, or the string "true" from a templated config """
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _text_claim(data, name):
    """ A claim that is a non-empty string, else None """
    value = data.get(name)
    return value if isinstance(value, str) and value else None


class Method:  # pylint: disable=E1101,R0903,W0201
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def _id_token_init(self):
        self.reset_id_token_cache()

    @web.method()
    def reset_id_token_cache(self):
        """ Forget discovered key locations and key clients (config may have changed) """
        self.jwk_clients = {}
        self.discovered_jwks_uri = None
        self.discovered_issuer = None

    @web.method()
    def get_id_token_source(self):
        """ Where ID token keys come from: public_key, jwks_uri, discovery or None """
        config = self.descriptor.config
        #
        if config.get("jwt_public_key"):
            return "public_key"
        if config.get("jwks_uri"):
            return "jwks_uri"
        if config.get("issuer") or (config.get("metadata_endpoint") or "").strip():
            return "discovery"
        return None

    @web.method()
    def check_id_token_config(self):
        """ Refuse to run with an ID token nobody verifies, unless asked to explicitly """
        source = self.get_id_token_source()
        if source is not None:
            log.info("ID token verification: keys from %s", source)
            return
        #
        if _is_true(self.descriptor.config.get("allow_unverified_id_token", False)):
            log.error(
                "ID token is NOT verified: no jwt_public_key, jwks_uri or issuer is "
                "configured and allow_unverified_id_token is set. Anyone who can "
                "reach the login callback can sign in as any user."
            )
            return
        #
        raise RuntimeError(
            "OIDC ID token verification is not configured: set jwt_public_key, "
            "jwks_uri or issuer (discovery), or set allow_unverified_id_token: true "
            "to accept unsigned ID tokens (insecure)"
        )

    @web.method()
    def get_jwks_uri(self):
        """ jwks_uri from config, or from the issuer's discovery document (once) """
        config = self.descriptor.config
        #
        if config.get("jwks_uri"):
            return config["jwks_uri"]
        #
        if self.discovered_jwks_uri is None:
            issuer = config.get("issuer")
            url = (config.get("metadata_endpoint") or "").strip() \
                or issuer.rstrip("/") + DISCOVERY_PATH
            #
            response = requests.get(
                url, verify=config.get("metadata_endpoint_verify", True), timeout=10,
            )
            response.raise_for_status()
            document = response.json()
            #
            if not isinstance(document, dict) or not isinstance(document.get("issuer"), str) \
                    or not document["issuer"]:
                raise ValueError("Discovery document has no issuer")
            # With issuer configured the document must agree; with metadata_endpoint
            # alone (an operator-configured HTTPS URL) the document's issuer is adopted
            if issuer and document["issuer"] != issuer:
                raise ValueError("Discovery document issuer does not match the configured issuer")
            if not isinstance(document.get("jwks_uri"), str) or not document["jwks_uri"]:
                raise ValueError("Discovery document has no jwks_uri")
            #
            self.discovered_jwks_uri = document["jwks_uri"]
            self.discovered_issuer = document["issuer"]
        #
        return self.discovered_jwks_uri

    @web.method()
    def get_id_token_key(self, id_token, source):
        """ The key that must have signed this ID token """
        if source == "public_key":
            return self.rsa_public_key
        #
        jwks_uri = self.get_jwks_uri()
        client = self.jwk_clients.get(jwks_uri)
        if client is None:
            client = jwt.PyJWKClient(jwks_uri, cache_keys=True, lifespan=JWKS_LIFESPAN)
            self.jwk_clients[jwks_uri] = client
        #
        return client.get_signing_key_from_jwt(id_token).key

    @web.method()
    def decode_id_token(self, id_token, expected_nonce):
        """ Verify an ID token and return its claims; raises if it must be refused

        Signature (keys from jwt_public_key, jwks_uri or discovery), audience,
        issuer, exp/nbf/iat and the nonce of this login. With no key source the
        token is only decoded, and only if allow_unverified_id_token is set.
        """
        config = self.descriptor.config
        source = self.get_id_token_source()
        #
        if source is None:
            if not _is_true(config.get("allow_unverified_id_token", False)):
                raise ValueError("No ID token verification source is configured")
            log.error("ID token is NOT verified (allow_unverified_id_token is set)")
            id_data = jwt.decode(id_token, options={"verify_signature": False})
        else:
            key = self.get_id_token_key(id_token, source)  # discovery runs here
            id_data = jwt.decode(
                id_token,
                key,
                algorithms=ALGORITHMS,
                audience=config["client_id"],
                issuer=config.get("issuer") or self.discovered_issuer or None,
                leeway=int(config.get("leeway", DEFAULT_LEEWAY)),
                options={"require": REQUIRED_CLAIMS},
            )
        #
        if not nonce_matches(expected_nonce, id_data.get("nonce")):
            raise ValueError("ID token nonce is missing or does not match this login")
        #
        return id_data

    @web.method()
    def build_identity(self, id_data):
        """ The immutable identity an ID token vouches for (None for what is absent) """
        return {
            "issuer": _text_claim(id_data, "iss"),
            "tid": _text_claim(id_data, "tid"),
            "oid": _text_claim(id_data, "oid"),
            "sub": _text_claim(id_data, "sub"),
        }

    @web.method()
    def build_delegation(self, oidc_token, now=None):
        """ What the token response is kept as, server-side, for the middle tier

        Lives in the session (Redis-backed in pylon_auth), never in the cookie and
        never among the attributes handed to processors and logs. Nothing reads it
        yet.
        """
        if now is None:
            now = time.time()
        #
        try:
            expires_at = int(now) + int(oidc_token["expires_in"])
        except (KeyError, TypeError, ValueError):
            expires_at = None
        #
        return {
            "access_token": oidc_token.get("access_token"),
            "refresh_token": oidc_token.get("refresh_token"),
            "expires_at": expires_at,
            "scope": oidc_token.get("scope"),
            "token_type": oidc_token.get("token_type"),
        }

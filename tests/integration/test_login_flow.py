"""The OIDC login and callback, end to end through the plugin's routes (#6941).

Covers what the validator matrix does not: the nonce and scope sent to the
provider, what reaches the session (server-side custody of the token response,
the immutable identity), and that no secret is ever written to the log.
"""
import time
import types
import urllib.parse

import pytest

from conftest import CLIENT_ID, ISSUER, OID, TID, make_token

ACCESS_TOKEN = "access-token-SECRET-aaaaaaaa"
REFRESH_TOKEN = "refresh-token-SECRET-bbbbbbbb"
CODE = "authorization-code-SECRET-cccccccc"


class TokenEndpoint:
    """requests, as the plugin uses it: post() to the token endpoint."""

    def __init__(self, response):
        self.response = response
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        response = self.response
        return types.SimpleNamespace(json=lambda: response)


@pytest.fixture
def token_endpoint(monkeypatch, login_mod):
    endpoint = TokenEndpoint({})
    monkeypatch.setattr(login_mod, "requests", types.SimpleNamespace(post=endpoint.post))
    return endpoint


@pytest.fixture
def module(build_module, signing_key):
    return build_module(jwt_public_key=signing_key.public_pem, issuer=ISSUER)


def start_login(module, flask, target="/target"):
    """Run /login and return what was sent to the provider."""
    flask.request.args = {"target_to": target}
    kind, url = module.login()
    assert kind == "REDIRECT"
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    return {key: values[0] for key, values in query.items()}


def callback(module, flask, sent, **args):
    flask.request.method = "GET"
    flask.request.args = {"state": sent["state"], "code": CODE, **args}
    return module.login_callback()


def token_response(signing_key, sent, **overrides):
    id_token = make_token(signing_key, nonce=sent["nonce"], **overrides)
    return {
        "id_token": id_token,
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "expires_in": 3599,
        "scope": "openid profile email offline_access",
        "token_type": "Bearer",
        "ext_expires_in": 3599,
    }


# --- authorization request ---------------------------------------------------


def test_login_sends_a_fresh_nonce_and_remembers_it(module, flask):
    first = start_login(module, flask)
    second = start_login(module, flask)

    assert len(first["nonce"]) >= 32
    assert first["nonce"] != second["nonce"]
    stored = {entry["nonce"] for entry in flask.session["auth_oidc"].values()}
    assert stored == {first["nonce"], second["nonce"]}


def test_login_sends_the_default_scope(module, flask):
    assert start_login(module, flask)["scope"] == "openid profile email"


def test_login_sends_the_configured_scope(build_module, signing_key, flask):
    module = build_module(
        jwt_public_key=signing_key.public_pem,
        scope="openid profile email offline_access api://middle-tier/.default",
    )

    assert start_login(module, flask)["scope"] == \
        "openid profile email offline_access api://middle-tier/.default"


def test_login_keeps_honouring_the_legacy_target_scope_key(build_module, signing_key, flask):
    module = build_module(jwt_public_key=signing_key.public_pem, target_scope="openid")

    assert start_login(module, flask)["scope"] == "openid"


def test_login_keeps_the_rest_of_the_request(module, flask):
    sent = start_login(module, flask)

    assert sent["response_type"] == "code"
    assert sent["client_id"] == CLIENT_ID
    assert sent["redirect_uri"] == "/auth_oidc.login_callback"


# --- callback ----------------------------------------------------------------


def test_a_good_callback_succeeds_and_stores_the_session(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask, target="/where")
    token_endpoint.response = token_response(signing_key, sent)

    result = callback(module, flask, sent)

    assert result == ("SUCCESS", "/where")
    saved = auth_core.saved
    assert saved["done"] is True
    assert saved["provider"] == "oidc"
    assert saved["provider_attr"]["nameid"] == "user@example.com"
    assert saved["provider_attr"]["attributes"]["sub"] == "sub-1"
    assert saved["provider_attr"]["sessionindex"] == token_endpoint.response["id_token"]


def test_the_state_is_single_use(module, flask, token_endpoint, signing_key):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)
    callback(module, flask, sent)

    assert callback(module, flask, sent) == "DENIED"


@pytest.mark.parametrize("overrides", [
    {"nonce": "attacker-chosen"},
    {"iss": "https://evil.example.com"},
    {"aud": "another-client"},
])
def test_a_bad_id_token_denies_the_login(module, flask, auth_core, token_endpoint, signing_key, log, overrides):
    sent = start_login(module, flask)
    response = token_response(signing_key, sent)
    response["id_token"] = make_token(signing_key, **{"nonce": sent["nonce"], **overrides})
    token_endpoint.response = response

    assert callback(module, flask, sent) == "DENIED"
    assert auth_core.saved is None
    assert any("ID token rejected" in line for line in log.lines("error"))


def test_a_token_signed_by_another_key_denies_the_login(module, flask, auth_core, token_endpoint, other_key):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(other_key, sent)

    assert callback(module, flask, sent) == "DENIED"
    assert auth_core.saved is None


def test_a_missing_nonce_denies_the_login(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask)
    response = token_response(signing_key, sent)
    response["id_token"] = make_token(signing_key, nonce=None)
    token_endpoint.response = response

    assert callback(module, flask, sent) == "DENIED"


def test_require_email_verified_still_applies(build_module, signing_key, flask, auth_core, token_endpoint):
    module = build_module(
        jwt_public_key=signing_key.public_pem, require_email_verified=True,
    )
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    assert callback(module, flask, sent) == "DENIED"


def test_the_id_token_response_type_checks_the_nonce_too(build_module, signing_key, flask, auth_core):
    module = build_module(
        jwt_public_key=signing_key.public_pem, target_response_type="id_token",
    )
    sent = start_login(module, flask)
    flask.request.method = "POST"
    flask.request.form = {
        "state": sent["state"], "id_token": make_token(signing_key, nonce="another"),
    }

    assert module.login_callback() == "DENIED"


def test_the_id_token_response_type_has_no_custody(build_module, signing_key, flask, auth_core):
    module = build_module(
        jwt_public_key=signing_key.public_pem, target_response_type="id_token",
    )
    sent = start_login(module, flask)
    flask.request.method = "POST"
    flask.request.form = {
        "state": sent["state"], "id_token": make_token(signing_key, nonce=sent["nonce"]),
    }

    assert module.login_callback()[0] == "SUCCESS"
    assert "delegation" not in auth_core.saved["provider_attr"]
    assert auth_core.saved["provider_attr"]["identity"]["oid"] == OID


# --- custody -----------------------------------------------------------------


def test_the_custody_dict_has_exactly_the_five_keys(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    callback(module, flask, sent)

    assert set(auth_core.saved["provider_attr"]["delegation"]) == {
        "access_token", "refresh_token", "expires_at", "scope", "token_type",
    }


def test_the_token_response_is_kept_server_side_under_delegation(
        module, flask, auth_core, token_endpoint, signing_key,
):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    before = int(time.time())
    callback(module, flask, sent)
    after = int(time.time())

    attr = auth_core.saved["provider_attr"]
    expires_at = attr["delegation"].pop("expires_at")
    assert before + 3599 <= expires_at <= after + 3599
    assert attr["delegation"] == {
        "access_token": ACCESS_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "scope": "openid profile email offline_access",
        "token_type": "Bearer",
    }



def test_custody_never_reaches_the_attributes(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    callback(module, flask, sent)

    attributes = auth_core.saved["provider_attr"]["attributes"]
    assert ACCESS_TOKEN not in repr(attributes)
    assert REFRESH_TOKEN not in repr(attributes)
    assert "delegation" not in attributes


def test_custody_tolerates_a_response_without_a_refresh_token(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask)
    response = token_response(signing_key, sent)
    for key in ("refresh_token", "expires_in", "scope"):
        del response[key]
    token_endpoint.response = response

    callback(module, flask, sent)

    delegation = auth_core.saved["provider_attr"]["delegation"]
    assert delegation["refresh_token"] is None
    assert delegation["expires_at"] is None
    assert delegation["scope"] is None
    assert delegation["access_token"] == ACCESS_TOKEN


def test_a_string_expires_in_is_accepted(module):
    delegation = module.build_delegation({"access_token": "a", "expires_in": "3600"}, now=100)

    assert delegation["expires_at"] == 3700


def test_an_unusable_expires_in_is_dropped(module):
    delegation = module.build_delegation({"access_token": "a", "expires_in": "soon"}, now=100)

    assert delegation["expires_at"] is None


# --- identity ----------------------------------------------------------------


def test_the_identity_carries_issuer_tid_oid_and_sub(module, flask, auth_core, token_endpoint, signing_key):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    callback(module, flask, sent)

    assert auth_core.saved["provider_attr"]["identity"] == {
        "issuer": ISSUER, "tid": TID, "oid": OID, "sub": "sub-1",
    }


def test_the_identity_has_none_for_claims_the_provider_did_not_send(module):
    identity = module.build_identity({"sub": "s", "iss": "i"})

    assert identity == {"issuer": "i", "tid": None, "oid": None, "sub": "s"}


def test_non_string_identity_claims_are_dropped(module):
    identity = module.build_identity({"sub": "s", "iss": "i", "tid": 5, "oid": ["x"]})

    assert identity["tid"] is None
    assert identity["oid"] is None


# --- redaction ---------------------------------------------------------------


def test_no_secret_reaches_the_log(module, flask, token_endpoint, signing_key, log):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)
    id_token = token_endpoint.response["id_token"]

    callback(module, flask, sent)

    logged = log.everything()
    for secret in (id_token, ACCESS_TOKEN, REFRESH_TOKEN, CODE, sent["nonce"]):
        assert secret not in logged
    assert id_token.split(".")[1] not in logged


def test_no_secret_reaches_the_log_when_the_login_is_refused(module, flask, token_endpoint, signing_key, log):
    sent = start_login(module, flask)
    response = token_response(signing_key, sent)
    response["id_token"] = make_token(signing_key, nonce="another")
    token_endpoint.response = response

    callback(module, flask, sent)

    logged = log.everything()
    for secret in (response["id_token"], ACCESS_TOKEN, REFRESH_TOKEN, CODE):
        assert secret not in logged


def test_the_log_names_claims_and_presence_only(module, flask, token_endpoint, signing_key, log):
    sent = start_login(module, flask)
    token_endpoint.response = token_response(signing_key, sent)

    callback(module, flask, sent)

    logged = log.everything()
    assert "oid" in logged and "tid" in logged and "sub" in logged
    assert "user@example.com" not in logged


def test_form_post_callbacks_do_not_log_the_posted_token(build_module, signing_key, flask, log):
    module = build_module(
        jwt_public_key=signing_key.public_pem, target_response_type="id_token",
    )
    sent = start_login(module, flask)
    id_token = make_token(signing_key, nonce=sent["nonce"])
    flask.request.method = "POST"
    flask.request.form = {"state": sent["state"], "id_token": id_token}

    module.login_callback()

    assert id_token not in log.everything()


def test_a_failed_token_exchange_denies_without_logging_the_code(module, flask, monkeypatch, login_mod, log):
    def boom(*args, **kwargs):
        raise ConnectionError(f"cannot reach the provider with {CODE}")

    monkeypatch.setattr(login_mod, "requests", types.SimpleNamespace(post=boom))
    sent = start_login(module, flask)

    assert callback(module, flask, sent) == "DENIED"
    assert CODE not in log.everything()


def test_a_token_response_that_is_not_an_object_denies_the_login(module, flask, auth_core, token_endpoint):
    sent = start_login(module, flask)
    token_endpoint.response = ["not", "an", "object"]

    assert callback(module, flask, sent) == "DENIED"
    assert auth_core.saved is None

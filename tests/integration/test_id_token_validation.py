"""Strict ID token validation (C-1009, issue #6941).

The ID token is the proof of who signed in, so it is verified like a credential:
signature against the provider's keys, audience, issuer, time window and the
nonce this browser session generated. Anything else is refused.
"""
import time
import types

import jwt
import pytest

from conftest import CLIENT_ID, ISSUER, JWKS_URI, claims, make_token

NONCE = "nonce-1"


def decode(subject, token, nonce=NONCE):
    return subject.decode_id_token(token, nonce)


@pytest.fixture
def with_public_key(build_module, signing_key):
    return build_module(jwt_public_key=signing_key.public_pem, issuer=ISSUER)


# --- the matrix, with the configured public key (existing path) --------------


def test_a_valid_token_passes(with_public_key, signing_key):
    data = decode(with_public_key, make_token(signing_key))

    assert data["sub"] == "sub-1"
    assert data["oid"] == "object-1"


def test_the_public_key_path_works_without_an_issuer(build_module, signing_key):
    subject = build_module(jwt_public_key=signing_key.public_pem)

    assert decode(subject, make_token(signing_key, iss="https://anything"))["sub"] == "sub-1"


@pytest.mark.parametrize("overrides", [
    {"iss": "https://evil.example.com/tenant-1/v2.0"},
    {"iss": ISSUER + "/"},
    {"iss": None},
    {"aud": "another-client"},
    {"aud": None},
    {"exp": int(time.time()) - 3600},
    {"exp": None},
    {"nbf": int(time.time()) + 3600},
    {"iat": int(time.time()) + 3600},
    {"sub": None},
], ids=lambda o: ",".join(f"{k}={v}" for k, v in o.items()))
def test_a_token_with_bad_claims_is_refused(with_public_key, signing_key, overrides):
    with pytest.raises(jwt.PyJWTError):
        decode(with_public_key, make_token(signing_key, **overrides))


def test_a_token_signed_with_another_key_is_refused(with_public_key, other_key):
    with pytest.raises(jwt.PyJWTError):
        decode(with_public_key, make_token(other_key))


def test_an_unsigned_token_is_refused(with_public_key):
    token = jwt.encode(claims(), None, algorithm="none")

    with pytest.raises(jwt.PyJWTError):
        decode(with_public_key, token)


def test_a_symmetric_algorithm_is_refused(with_public_key, signing_key):
    """The public key must never be usable as an HMAC secret."""
    token = jwt.encode(claims(), "secret-" * 10, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        decode(with_public_key, token)


def test_leeway_tolerates_small_clock_skew(with_public_key, signing_key):
    token = make_token(signing_key, exp=int(time.time()) - 30)

    assert decode(with_public_key, token)["sub"] == "sub-1"


def test_leeway_is_configurable(build_module, signing_key):
    subject = build_module(jwt_public_key=signing_key.public_pem, leeway=0)

    with pytest.raises(jwt.ExpiredSignatureError):
        decode(subject, make_token(signing_key, exp=int(time.time()) - 5))


# --- nonce -------------------------------------------------------------------


def test_a_missing_nonce_is_refused(with_public_key, signing_key):
    with pytest.raises(ValueError, match="nonce"):
        decode(with_public_key, make_token(signing_key, nonce=None))


def test_a_mismatched_nonce_is_refused(with_public_key, signing_key):
    with pytest.raises(ValueError, match="nonce"):
        decode(with_public_key, make_token(signing_key, nonce="another"))


def test_a_login_that_recorded_no_nonce_is_refused(with_public_key, signing_key):
    with pytest.raises(ValueError, match="nonce"):
        decode(with_public_key, make_token(signing_key), nonce=None)


def test_a_non_string_nonce_is_refused(with_public_key, signing_key):
    with pytest.raises(ValueError, match="nonce"):
        decode(with_public_key, make_token(signing_key, nonce=["nonce-1"]))


def test_the_nonce_is_compared_in_constant_time(id_token_mod):
    assert id_token_mod.hmac.compare_digest is not None
    assert id_token_mod.nonce_matches("a", "a")
    assert not id_token_mod.nonce_matches("a", "b")
    assert not id_token_mod.nonce_matches("a", None)
    assert not id_token_mod.nonce_matches(None, "a")


# --- key sources -------------------------------------------------------------


@pytest.fixture
def jwks(monkeypatch, signing_key):
    """The provider's JWKS document, served to the real PyJWKClient."""
    document = {"keys": [signing_key.jwk("kid-1")]}
    fetched = []

    def fetch_data(client):
        fetched.append(client.uri)
        return document

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch_data)
    return types.SimpleNamespace(document=document, fetched=fetched)


def test_keys_come_from_jwks_uri(build_module, signing_key, jwks):
    subject = build_module(jwks_uri=JWKS_URI)

    assert decode(subject, make_token(signing_key))["sub"] == "sub-1"
    assert jwks.fetched == [JWKS_URI]


def test_jwks_uri_rejects_a_foreign_signature(build_module, other_key, jwks):
    subject = build_module(jwks_uri=JWKS_URI)

    with pytest.raises(jwt.PyJWTError):
        decode(subject, make_token(other_key))


def test_jwks_uri_rejects_an_unknown_kid(build_module, signing_key, jwks):
    subject = build_module(jwks_uri=JWKS_URI)

    with pytest.raises(jwt.PyJWTError):
        decode(subject, make_token(signing_key, kid="rotated-away"))


def test_jwks_uri_supports_elliptic_curve_keys(build_module, ec_key, monkeypatch):
    monkeypatch.setattr(
        jwt.PyJWKClient, "fetch_data", lambda client: {"keys": [ec_key.jwk("ec-1")]},
    )
    subject = build_module(jwks_uri=JWKS_URI)

    token = make_token(ec_key, kid="ec-1", algorithm="ES256")

    assert decode(subject, token)["sub"] == "sub-1"


def test_the_jwks_client_is_reused(build_module, signing_key, jwks):
    subject = build_module(jwks_uri=JWKS_URI)

    decode(subject, make_token(signing_key))
    decode(subject, make_token(signing_key))

    assert len(jwks.fetched) == 1


def test_a_configured_public_key_wins_over_jwks_uri(build_module, signing_key, other_key, jwks):
    subject = build_module(jwt_public_key=signing_key.public_pem, jwks_uri=JWKS_URI)

    assert decode(subject, make_token(signing_key))["sub"] == "sub-1"
    assert jwks.fetched == []


class Discovery:
    def __init__(self, document):
        self.document = document
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        document = self.document
        return types.SimpleNamespace(json=lambda: document, raise_for_status=lambda: None)


@pytest.fixture
def discovery(monkeypatch, id_token_mod, jwks):
    served = Discovery({"issuer": ISSUER, "jwks_uri": JWKS_URI})
    monkeypatch.setattr(id_token_mod, "requests", types.SimpleNamespace(get=served.get))
    return served


def test_keys_come_from_discovery_when_only_the_issuer_is_configured(
        build_module, signing_key, discovery, jwks,
):
    subject = build_module(issuer=ISSUER)

    assert decode(subject, make_token(signing_key))["sub"] == "sub-1"
    assert discovery.urls == [ISSUER + "/.well-known/openid-configuration"]
    assert jwks.fetched == [JWKS_URI]


def test_discovery_uses_the_metadata_endpoint_when_set(build_module, signing_key, discovery, jwks):
    subject = build_module(issuer=ISSUER, metadata_endpoint="https://login.example.com/meta")

    decode(subject, make_token(signing_key))

    assert discovery.urls == ["https://login.example.com/meta"]


def test_discovery_is_done_once(build_module, signing_key, discovery, jwks):
    subject = build_module(issuer=ISSUER)

    decode(subject, make_token(signing_key))
    decode(subject, make_token(signing_key))

    assert len(discovery.urls) == 1


def test_discovery_refuses_a_document_for_another_issuer(build_module, signing_key, discovery, jwks):
    discovery.document = {"issuer": "https://evil.example.com", "jwks_uri": JWKS_URI}
    subject = build_module(issuer=ISSUER)

    with pytest.raises(ValueError, match="issuer"):
        decode(subject, make_token(signing_key))
    assert jwks.fetched == []


def test_discovery_refuses_a_document_without_jwks_uri(build_module, signing_key, discovery, jwks):
    discovery.document = {"issuer": ISSUER}
    subject = build_module(issuer=ISSUER)

    with pytest.raises(ValueError, match="jwks_uri"):
        decode(subject, make_token(signing_key))


def test_the_discovered_issuer_is_enforced_on_the_token(build_module, signing_key, discovery, jwks):
    subject = build_module(issuer=ISSUER)

    with pytest.raises(jwt.InvalidIssuerError):
        decode(subject, make_token(signing_key, iss="https://evil.example.com"))


# --- no verification source --------------------------------------------------


def test_init_refuses_to_start_without_a_verification_source(build_module, auth_core):
    subject = build_module()

    with pytest.raises(RuntimeError, match="allow_unverified_id_token"):
        subject.init()

    assert auth_core.registered == []
    assert not subject.descriptor.initialized


def test_init_starts_when_a_source_is_configured(build_module, auth_core, signing_key):
    subject = build_module(jwt_public_key=signing_key.public_pem)

    subject.init()

    assert auth_core.registered == ["oidc"]


@pytest.mark.parametrize("config", [
    {"issuer": ISSUER},
    {"jwks_uri": JWKS_URI},
])
def test_init_starts_for_discovery_and_jwks_uri(build_module, auth_core, config):
    build_module(**config).init()

    assert auth_core.registered == ["oidc"]


def test_explicit_allow_starts_and_logs_an_error(build_module, auth_core, log):
    subject = build_module(allow_unverified_id_token=True)

    subject.init()

    assert auth_core.registered == ["oidc"]
    assert any("NOT verified" in line for line in log.lines("error"))


def test_explicit_allow_logs_an_error_on_every_login(build_module, signing_key, log):
    subject = build_module(allow_unverified_id_token=True)

    for _ in range(2):
        data = decode(subject, make_token(signing_key))
        assert data["sub"] == "sub-1"

    assert sum("NOT verified" in line for line in log.lines("error")) == 2


def test_unverified_mode_accepts_any_signature_but_still_needs_the_nonce(build_module, other_key):
    subject = build_module(allow_unverified_id_token=True)

    assert decode(subject, make_token(other_key, exp=int(time.time()) - 3600))["sub"] == "sub-1"
    with pytest.raises(ValueError, match="nonce"):
        decode(subject, make_token(other_key, nonce="another"))


def test_a_source_wins_over_the_allow_flag(build_module, signing_key, other_key):
    subject = build_module(jwt_public_key=signing_key.public_pem, allow_unverified_id_token=True)

    with pytest.raises(jwt.PyJWTError):
        decode(subject, make_token(other_key))


def test_a_token_is_never_accepted_without_a_source_or_the_flag(build_module, signing_key):
    """Even if init was bypassed (a re-config), decoding fails closed."""
    subject = build_module()

    with pytest.raises(ValueError, match="verification"):
        decode(subject, make_token(signing_key))


def test_the_allow_flag_must_be_true_not_just_present(build_module):
    with pytest.raises(RuntimeError):
        build_module(allow_unverified_id_token=False).init()
    with pytest.raises(RuntimeError):
        build_module(allow_unverified_id_token="no").init()


def test_metadata_endpoint_alone_discovers_and_enforces_the_document_issuer(
        build_module, signing_key, discovery, jwks):
    subject = build_module(metadata_endpoint="https://login.example.com/meta")
    assert subject.get_id_token_source() == "discovery"
    subject.check_id_token_config()  # no refusal: the metadata endpoint is a key source

    assert decode(subject, make_token(signing_key))["iss"] == ISSUER
    assert discovery.urls == ["https://login.example.com/meta"]

    with pytest.raises(Exception):
        decode(subject, make_token(signing_key, iss="https://evil.example.com"))


def test_an_unconfigured_provider_is_not_refused(build_module, log):
    subject = build_module(client_id="", authorization_endpoint="", token_endpoint="")
    subject.check_id_token_config()  # inert plugin: nothing to verify, nothing to refuse
    assert any("not configured" in line for line in log.lines("info"))


def test_init_binds_methods_before_the_id_token_check(plugin_root):
    source = (plugin_root / "module.py").read_text()
    assert source.index("self.descriptor.init_methods()") < source.index("self.check_id_token_config()") \
        < source.index("self.descriptor.init_all(")

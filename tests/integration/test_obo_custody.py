"""Custody of a Microsoft sign-in for on-behalf-of exchanges, and the assertion RPC (C-1009 #6756 step 4).

Through the plugin's real login callback, logout and RPC; Redis and the token endpoint are fakes. Every token here is
made up for the tests and never signed by anyone real.
"""
import base64
import datetime
import hashlib
import hmac
import json
import secrets
import time
import types
import urllib.parse

import pytest

from conftest import CLIENT_ID, make_token

TID = "11111111-2222-3333-4444-555555555555"
OID = "oid-42"
ENTRA = f"https://login.microsoftonline.com/{TID}/v2.0"
REFRESH_TOKEN = "refresh-token-made-up-dddd"
NEW_REFRESH_TOKEN = "refresh-token-made-up-eeee"
REQUEST_KEY = "custody-request-key-made-up-for-tests-0123"


def signed(tid, oid, refresh=False, key=REQUEST_KEY, iat=None, nonce=None):
    """What elitea_core sends: the request, its time, a fresh nonce and the signature over them."""
    iat = int(time.time()) if iat is None else iat
    nonce = nonce or secrets.token_urlsafe(16)
    message = "|".join(("v1", str(tid), str(oid), "1" if refresh else "0", str(iat), nonce)).encode()
    return {"tid": tid, "oid": oid, "refresh": refresh, "iat": iat, "nonce": nonce,
            "signature": hmac.new(key.encode(), message, hashlib.sha256).hexdigest()}


def ask(module, tid, oid, refresh=False, **over):
    return module.obo_assertion(**{**signed(tid, oid, refresh), **over})


def jwt(**claims):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


ACCESS = jwt(iss=ENTRA, tid=TID, oid=OID, aud="api-client", scp="access_as_user")
NEW_ACCESS = jwt(iss=ENTRA, tid=TID, oid=OID, aud="api-client", scp="access_as_user", n=2)


class Redis:
    def __init__(self):
        self.values, self.ttls, self.calls = {}, {}, []

    def set(self, key, value, ex=None, keepttl=False, nx=False, xx=False):
        if (nx and key in self.values) or (xx and key not in self.values):
            return None
        if ":nonce:" not in key:
            self.calls.append(("set", key, ex, keepttl))
        self.values[key] = value
        if not keepttl:
            self.ttls[key] = ex
        return True

    def get(self, key):
        return self.values.get(key)

    def ttl(self, key):
        return (self.ttls.get(key) or -1) if key in self.values else -2

    def pipeline(self, transaction=True):
        return Pipeline(self)

    def delete(self, key):
        self.calls.append(("delete", key))
        self.values.pop(key, None)


class Pipeline:
    """MULTI/EXEC as the RPC uses it: the queued reads answered together."""

    def __init__(self, redis):
        self.redis, self.queued = redis, []

    def get(self, key):
        self.queued.append(("get", key))

    def ttl(self, key):
        self.queued.append(("ttl", key))

    def execute(self):
        return [getattr(self.redis, name)(key) for name, key in self.queued]


class TokenEndpoint:
    def __init__(self):
        self.posts, self.response = [], {}

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        response = self.response
        return types.SimpleNamespace(json=lambda: response, status_code=200)


class Session:
    """requests.Session as the refresh uses it."""

    def __init__(self, endpoint):
        self.endpoint, self.trust_env, self.max_redirects, self.proxies = endpoint, True, 30, None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, **kwargs):
        self.endpoint.posts.append((url, {**kwargs, "_trust_env": self.trust_env,
                                          "_max_redirects": self.max_redirects, "_proxies": self.proxies}))
        status, body = self.endpoint.refresh
        return Answer(status, json.dumps(body).encode())


class Answer:
    """A streamed response: the refresh reads its body in bounded chunks (C9-SEC-58)."""

    def __init__(self, status, raw):
        self.status_code, self.raw = status, raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_content(self, chunk_size=1):
        for start in range(0, len(self.raw), chunk_size):
            yield self.raw[start:start + chunk_size]


class AppShim:
    """pylon's app shim, as auth_oidc meets it at runtime: a few proxied attributes, a RuntimeError for any other."""

    def __init__(self, **proxied):
        self.__dict__["_proxied"] = proxied

    def __getattr__(self, name):
        if name in self._proxied:
            return self._proxied[name]
        raise RuntimeError("Not supported")

    def __setattr__(self, name, value):
        self._proxied[name] = value


@pytest.fixture
def redis():
    return Redis()


@pytest.fixture
def endpoint(monkeypatch, login_mod, custody_mod):
    found = TokenEndpoint()
    found.refresh = (200, {"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH_TOKEN, "expires_in": 3600})
    monkeypatch.setattr(login_mod, "requests", types.SimpleNamespace(post=found.post))
    monkeypatch.setattr(custody_mod, "requests", types.SimpleNamespace(Session=lambda: Session(found)))
    return found


@pytest.fixture(autouse=True)
def request_key(monkeypatch):
    monkeypatch.setenv("ELITEA_OBO_CUSTODY_KEY", REQUEST_KEY)


@pytest.fixture
def make(build_module, signing_key, redis):
    def build(**config):
        config.setdefault("obo_custody_enabled", True)
        config.setdefault("obo_api_client_id", "api-client")
        config.setdefault("token_endpoint", f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token")
        config.setdefault("scope", "openid profile offline_access api://api-client/access_as_user")
        module = build_module(jwt_public_key=signing_key.public_pem, issuer=config.pop("issuer", ENTRA), **config)
        module.context.app = AppShim(secret_key=module.context.app.secret_key,
                                     session_interface=types.SimpleNamespace(client=redis),
                                     config={"PERMANENT_SESSION_LIFETIME": "604800"})   # as pylon.yml sets it
        module.context.settings = {"sessions": {"prefix": "p_auth_session_"}}
        module.events = []
        module.context.event_manager = types.SimpleNamespace(
            fire_event=lambda name, payload: module.events.append((name, payload)))
        return module
    return build


def sign_in(module, flask, endpoint, signing_key, *, access=ACCESS, issuer=ENTRA, oid=OID):
    flask.request.args = {"target_to": "/"}
    _, url = module.login()
    sent = {key: values[0] for key, values in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()}
    endpoint.response = {
        "id_token": make_token(signing_key, nonce=sent["nonce"], iss=issuer, tid=TID, oid=oid, aud=CLIENT_ID),
        "access_token": access, "refresh_token": REFRESH_TOKEN, "expires_in": 3599, "token_type": "Bearer"}
    flask.request.method = "GET"
    flask.request.args = {"state": sent["state"], "code": "code-made-up"}
    return module.login_callback()


KEY = f"c1009_obo_custody:{TID}:{OID}"


def test_a_microsoft_sign_in_is_kept_under_the_persons_subject(make, flask, endpoint, signing_key, redis, log, auth_core):
    module = make()
    assert sign_in(module, flask, endpoint, signing_key)[0] == "SUCCESS"
    record = json.loads(redis.values[KEY])
    assert {key: record[key] for key in ("issuer", "tid", "oid", "assertion_source", "access_token", "refresh_token")} == {
        "issuer": ENTRA, "tid": TID, "oid": OID, "assertion_source": "login", "access_token": ACCESS,
        "refresh_token": REFRESH_TOKEN}
    assert redis.ttls[KEY] == 7 * 86400   # as long as the session lives
    assert auth_core.saved["provider_attr"]["delegation"]["access_token"] == ACCESS   # the session keeps it as before
    assert ACCESS not in log.everything() and REFRESH_TOKEN not in log.everything()


def test_custody_is_off_unless_switched_on(make, flask, endpoint, signing_key, redis):
    sign_in(make(obo_custody_enabled=False), flask, endpoint, signing_key)
    assert redis.values == {}


@pytest.mark.parametrize("access, issuer, oid", [
    (ACCESS, "https://keycloak.example/realms/elitea", OID),                      # a Keycloak (brokered) login
    (jwt(iss=ENTRA, tid=TID, oid="someone-else", aud="api-client"), ENTRA, OID),   # an access token of someone else
    (jwt(iss="https://evil.example/v2.0", tid=TID, oid=OID, aud="api-client"), ENTRA, OID),   # not issued by Entra
    (jwt(iss=ENTRA, tid=TID, oid=OID, aud="https://graph.microsoft.com"), ENTRA, OID),     # a token for another API
    ("opaque-access-token", ENTRA, OID),
])
def test_only_microsofts_own_token_of_the_proven_identity_is_kept(make, flask, endpoint, signing_key, redis,
                                                                    access, issuer, oid):
    sign_in(make(issuer=issuer), flask, endpoint, signing_key, access=access, issuer=issuer, oid=oid)
    assert redis.values == {}


@pytest.mark.parametrize("change", [
    {"signature": "0" * 64},                                   # not elitea_core's
    {"iat": int(time.time()) - 120},                           # too old (the signature is over the old time)
    {"nonce": "x"},                                            # not a nonce
    {"refresh": True},                                         # signed for another request
])
def test_a_request_that_elitea_core_did_not_sign_is_refused(make, flask, endpoint, signing_key, change):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    request = signed(TID, OID, iat=change.get("iat"), nonce=change.get("nonce"))
    request.update({key: value for key, value in change.items() if key in ("signature", "refresh")})
    assert module.obo_assertion(**request) == {"ok": False, "code": "REQUEST_REFUSED"}
    assert endpoint.posts[1:] == []


def test_a_signed_request_is_answered_once(make, flask, endpoint, signing_key):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    request = signed(TID, OID)
    assert module.obo_assertion(**request)["ok"] is True
    assert module.obo_assertion(**request) == {"ok": False, "code": "REQUEST_REFUSED"}   # a replay


def test_without_the_request_key_every_request_is_refused(make, flask, endpoint, signing_key, monkeypatch):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    monkeypatch.delenv("ELITEA_OBO_CUSTODY_KEY")
    assert ask(module, TID, OID) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}   # custody is off without its key


def test_the_assertion_is_handed_out_for_the_person_and_nobody_else(make, flask, endpoint, signing_key, redis):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    assert ask(module, TID, OID)["assertion"] == ACCESS
    assert ask(module, TID, "someone-else") == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert ask(module, "../x", OID)["ok"] is False and ask(module, None, None)["ok"] is False
    assert endpoint.posts[1:] == []   # nothing but the login's own code exchange


def test_a_refresh_renews_once_through_a_hardened_request_and_keeps_the_custody_lifetime(
        make, flask, endpoint, signing_key, redis, log):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    answer = ask(module, TID, OID, refresh=True)
    assert answer["ok"] is True and answer["assertion"] == NEW_ACCESS
    url, kwargs = endpoint.posts[-1]
    assert url == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
    assert kwargs["data"]["grant_type"] == "refresh_token" and kwargs["data"]["refresh_token"] == REFRESH_TOKEN
    assert (kwargs["allow_redirects"], kwargs["timeout"], kwargs["_trust_env"], kwargs["_max_redirects"],
            kwargs["_proxies"]) == (False, 4, False, 0, {})
    assert json.loads(redis.values[KEY])["refresh_token"] == NEW_REFRESH_TOKEN
    assert redis.calls[-1] == ("set", KEY, None, True)
    assert "refreshed" in "\n".join(log.lines())
    for secret in (ACCESS, NEW_ACCESS, REFRESH_TOKEN, NEW_REFRESH_TOKEN):
        assert secret not in log.everything()


def test_the_answer_says_when_the_custody_ends_and_never_later_than_the_session_lifetime(
        make, flask, endpoint, signing_key, redis):
    """#7281: elitea_core keeps no token minted from a custody past the custody's own end (fixed at the sign-in)."""
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    answer = ask(module, TID, OID)
    assert 0 <= (time.time() + 7 * 86400) - answer["custody_expires_at"] <= 2
    refreshed = ask(module, TID, OID, refresh=True)   # a refresh keeps the end where the sign-in put it
    assert refreshed["ok"] is True and refreshed["custody_expires_at"] == answer["custody_expires_at"]
    redis.ttls[KEY] = 120   # the custody's own clock runs down: the answer follows it
    assert 0 <= time.time() + 120 - ask(module, TID, OID)["custody_expires_at"] <= 2
    del redis.values[KEY]
    assert ask(module, TID, OID) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}


def test_a_custody_that_ends_between_the_reads_or_has_no_lifetime_never_lets_main_keep_a_token(
        make, flask, endpoint, signing_key, redis, monkeypatch):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    monkeypatch.setattr(redis, "ttl", lambda key: -2)   # gone between the record read and its lifetime
    assert ask(module, TID, OID) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    monkeypatch.setattr(redis, "ttl", lambda key: -1)   # no lifetime at all: treated as ending now
    assert 0 <= time.time() - ask(module, TID, OID)["custody_expires_at"] <= 2


def test_a_refresh_does_not_bring_back_a_custody_that_ended_meanwhile(make, flask, endpoint, signing_key, redis,
                                                                         monkeypatch):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    real_refresh = module.refresh_obo_custody

    def refresh_while_it_ends(record):
        redis.values.pop(KEY, None)   # the custody expires while the refresh is on the wire
        return real_refresh(record)

    monkeypatch.setattr(module, "refresh_obo_custody", refresh_while_it_ends)
    assert ask(module, TID, OID, refresh=True) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert KEY not in redis.values   # not written back without a lifetime


def test_an_access_token_about_to_expire_is_refreshed_without_being_asked(make, flask, endpoint, signing_key, redis):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    record = json.loads(redis.values[KEY])
    record["expires_at"] = int(time.time()) + 30
    redis.values[KEY] = json.dumps(record)
    assert ask(module, TID, OID)["assertion"] == NEW_ACCESS


@pytest.mark.parametrize("refresh", [(400, {"error": "invalid_grant"}),
                                     (200, {"access_token": jwt(iss=ENTRA, tid=TID, oid="someone-else", aud="api-client"),
                                            "expires_in": 3600})])
def test_a_refused_or_foreign_refresh_answers_unavailable_and_keeps_the_record(make, flask, endpoint, signing_key,
                                                                                 redis, refresh):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    before = redis.values[KEY]
    endpoint.refresh = refresh
    assert ask(module, TID, OID, refresh=True) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert redis.values[KEY] == before


def test_a_refresh_is_never_sent_over_plain_http(make, flask, endpoint, signing_key, redis):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    posts = len(endpoint.posts)
    for url in (f"http://login.microsoftonline.com/{TID}/oauth2/v2.0/token", "https://keycloak.example/token",
                f"https://login.microsoftonline.com:8443/{TID}/oauth2/v2.0/token"):
        module.descriptor.config["token_endpoint"] = url
        assert ask(module, TID, OID, refresh=True)["ok"] is False and len(endpoint.posts) == posts


def test_signing_out_drops_the_custody(make, flask, endpoint, signing_key, redis, auth_core):
    module = make(logout_mode="local", end_session_endpoint="https://login.microsoftonline.com/logout")
    sign_in(module, flask, endpoint, signing_key)
    auth_core.context = auth_core.saved
    auth_core.logout_success_redirect = lambda target: ("LOGGED_OUT", target)
    flask.request.args = {}
    assert module.logout()[0] == "LOGGED_OUT"
    assert KEY not in redis.values
    assert ask(module, TID, OID)["ok"] is False
    assert module.events == [("auth_oidc_obo_custody_dropped", {"tid": TID, "oid": OID})]   # Main drops its tokens



@pytest.mark.parametrize("unset", ["key", "api_client_id"])
def test_custody_switched_on_without_its_key_or_audience_keeps_nothing_and_says_so(
        make, flask, endpoint, signing_key, redis, log, monkeypatch, unset):
    if unset == "key":
        monkeypatch.setenv("ELITEA_OBO_CUSTODY_KEY", "too-short")
        module = make()
    else:
        module = make(obo_api_client_id=None)
    log.clear()
    assert module.check_obo_custody_config() is False
    assert any(level == "error" and "OBO custody is enabled" in text for level, text, _ in log.records)
    sign_in(module, flask, endpoint, signing_key)
    assert redis.values == {}


def test_a_complete_custody_configuration_passes_the_init_check(make):
    assert make().check_obo_custody_config() is True and make(obo_custody_enabled=False).check_obo_custody_config()


def test_the_refresh_never_turns_off_tls_verification(make, flask, endpoint, signing_key):
    module = make(token_endpoint_verify=False)
    sign_in(module, flask, endpoint, signing_key)
    assert ask(module, TID, OID, refresh=True)["ok"] is True
    assert endpoint.posts[-1][1]["verify"] is True


@pytest.mark.parametrize("lifetime, expected", [
    (datetime.timedelta(hours=2), 7200), (3600, 3600), ("abc", 86400), (None, 86400), (0, 86400)])
def test_the_custody_lifetime_comes_from_the_session_lifetime_config(make, lifetime, expected):
    module = make()
    module.context.app.config["PERMANENT_SESSION_LIFETIME"] = lifetime
    assert module.obo_custody_ttl() == expected


def test_custody_is_kept_behind_pylons_app_shim(make, flask, endpoint, signing_key, redis, log):
    """Regression (Phase 2, 2026-10-28): the lifetime was read from an attribute the shim does not proxy."""
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    assert KEY in redis.values and "OBO custody was not kept" not in log.everything()


def test_an_oversized_refresh_answer_is_refused_without_reading_it_all(make, flask, endpoint, signing_key, redis):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    endpoint.refresh = (200, {"access_token": NEW_ACCESS, "padding": "x" * 70_000})
    assert ask(module, TID, OID, refresh=True) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert json.loads(redis.values[KEY])["access_token"] == ACCESS


# --- #7131: the offline consent of a mandate owner -------------------------------------------------------------------

HOLDER = "mandate:6f1c1d1e-0000-4000-8000-000000000001"
OFFLINE_REFRESH_TOKEN = "refresh-token-made-up-ffff"


def signed_offline(fields, key=REQUEST_KEY, iat=None, nonce=None):
    iat = int(time.time()) if iat is None else iat
    nonce = nonce or secrets.token_urlsafe(16)
    message = "|".join((*fields, str(iat), nonce)).encode()
    return {"iat": iat, "nonce": nonce, "signature": hmac.new(key.encode(), message, hashlib.sha256).hexdigest()}


def grant(module, tid=TID, oid=OID, **over):
    request = {"tid": tid, "oid": oid, "holder": HOLDER, **signed_offline(("v1-offline-grant", tid, oid, HOLDER))}
    return module.obo_offline_grant(**{**request, **over}), request


def opened(custody_mod, sealed, direction, nonce, key=REQUEST_KEY):
    return custody_mod.open_sealed(custody_mod.seal_key(key), sealed,
                                   custody_mod.seal_aad(direction, TID, OID, HOLDER, nonce))


def redeem(module, custody_mod, refresh_token=OFFLINE_REFRESH_TOKEN, source="login", seal_with=REQUEST_KEY,
           signed_sealed=None, **over):
    """``over`` changes the request after it was signed (``source`` is signed as given)."""
    nonce = secrets.token_urlsafe(16)
    sealed = custody_mod.seal(custody_mod.seal_key(seal_with), refresh_token,
                              custody_mod.seal_aad("redeem-req", TID, OID, HOLDER, nonce))
    digest = hashlib.sha256((signed_sealed or sealed).encode()).hexdigest()
    request = {"tid": TID, "oid": OID, "holder": HOLDER, "source": source, "sealed_refresh_token": sealed,
               **signed_offline(("v1-offline", TID, OID, HOLDER, source, digest), nonce=nonce)}
    request.update(over)
    return module.obo_offline_assertion(**request), request


def test_consent_hands_out_a_fresh_refresh_token_sealed_and_leaves_the_custody_alone(
        make, flask, endpoint, signing_key, redis, log, custody_mod):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    kept = redis.values[KEY]
    answer, request = grant(module)
    assert (answer["ok"], answer["assertion_source"]) == (True, "login")
    assert NEW_REFRESH_TOKEN not in json.dumps(answer)   # never in plain text on the bus
    assert opened(custody_mod, answer["sealed_refresh_token"], "grant-reply", request["nonce"]) == NEW_REFRESH_TOKEN
    assert opened(custody_mod, answer["sealed_refresh_token"], "redeem-reply", request["nonce"]) is None
    assert opened(custody_mod, answer["sealed_refresh_token"], "grant-reply", request["nonce"],
                  key="another-request-key-made-up-0123456789") is None
    url, kwargs = endpoint.posts[-1]
    assert url == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
    assert kwargs["data"]["grant_type"] == "refresh_token" and kwargs["data"]["refresh_token"] == REFRESH_TOKEN
    assert (kwargs["allow_redirects"], kwargs["_trust_env"], kwargs["_max_redirects"]) == (False, False, 0)
    assert redis.values[KEY] == kept   # the session's own custody is not touched
    for secret in (ACCESS, NEW_ACCESS, REFRESH_TOKEN, NEW_REFRESH_TOKEN):
        assert secret not in log.everything()


@pytest.mark.parametrize("change", [
    {"signature": "0" * 64},
    {"holder": "mandate:6f1c1d1e-0000-4000-8000-000000000002"},   # signed for another mandate
    {"holder": "user:9"},                                          # not a mandate
    {"iat": int(time.time()) - 120},
])
def test_a_consent_request_elitea_core_did_not_sign_for_this_mandate_is_refused(
        make, flask, endpoint, signing_key, change):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    if "iat" in change:
        request = {"tid": TID, "oid": OID, "holder": HOLDER,
                   **signed_offline(("v1-offline-grant", TID, OID, HOLDER), iat=change["iat"])}
        assert module.obo_offline_grant(**request) == {"ok": False, "code": "REQUEST_REFUSED"}
    else:
        assert grant(module, **change)[0] == {"ok": False, "code": "REQUEST_REFUSED"}
    assert endpoint.posts[1:] == []


def test_a_custody_assertion_signature_never_opens_a_consent(make, flask, endpoint, signing_key):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    other = signed(TID, OID)   # a v1 assertion request of the same person
    assert module.obo_offline_grant(tid=TID, oid=OID, holder=HOLDER, iat=other["iat"], nonce=other["nonce"],
                                    signature=other["signature"]) == {"ok": False, "code": "REQUEST_REFUSED"}


def test_a_consent_request_is_answered_once(make, flask, endpoint, signing_key):
    module = make()
    sign_in(module, flask, endpoint, signing_key)
    answer, request = grant(module)
    assert answer["ok"] is True
    assert module.obo_offline_grant(**request) == {"ok": False, "code": "REQUEST_REFUSED"}


def test_consent_without_a_kept_sign_in_or_its_refresh_token_or_a_working_refresh_is_unavailable(
        make, flask, endpoint, signing_key, redis):
    module = make()
    assert grant(module)[0] == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}   # never signed in
    sign_in(module, flask, endpoint, signing_key)
    endpoint.refresh = (400, {"error": "invalid_grant"})
    assert grant(module)[0] == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    record = json.loads(redis.values[KEY])
    redis.values[KEY] = json.dumps({**record, "refresh_token": None})
    assert grant(module)[0] == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert grant(module, oid="someone-else")[0]["ok"] is False


def test_a_sealed_refresh_token_is_redeemed_and_its_rotation_returned_sealed(make, endpoint, log, redis, custody_mod):
    module = make()
    answer, request = redeem(module, custody_mod)
    assert answer["ok"] is True and answer["assertion"] == NEW_ACCESS
    assert NEW_REFRESH_TOKEN not in json.dumps(answer) and OFFLINE_REFRESH_TOKEN not in json.dumps(request)
    assert opened(custody_mod, answer["sealed_refresh_token"], "redeem-reply", request["nonce"]) == NEW_REFRESH_TOKEN
    url, kwargs = endpoint.posts[-1]
    assert url == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"
    assert kwargs["data"]["refresh_token"] == OFFLINE_REFRESH_TOKEN
    assert [key for key in redis.values if ":nonce:" not in key] == []   # nothing is kept
    endpoint.refresh = (200, {"access_token": NEW_ACCESS, "expires_in": 3600})   # no rotation
    assert redeem(module, custody_mod)[0]["sealed_refresh_token"] is None
    for secret in (NEW_ACCESS, OFFLINE_REFRESH_TOKEN, NEW_REFRESH_TOKEN):
        assert secret not in log.everything()


@pytest.mark.parametrize("answer, code", [
    ((400, {"error": "invalid_grant"}), "CONSENT_REFUSED"),            # expired or revoked at Microsoft: definitive
    ((400, {"error": "invalid_client"}), "ASSERTION_UNAVAILABLE"),     # the client, not the consent
    ((503, {}), "ASSERTION_UNAVAILABLE"),
    ((200, {"access_token": jwt(iss=ENTRA, tid=TID, oid="someone-else", aud="api-client"), "expires_in": 3600}),
     "ASSERTION_UNAVAILABLE"),                                          # another person's token is never handed out
])
def test_a_refused_redemption_says_whether_the_consent_itself_is_gone(make, endpoint, custody_mod, answer, code):
    endpoint.refresh = answer
    assert redeem(make(), custody_mod)[0] == {"ok": False, "code": code}


def _tampered(sealed):
    head, body = sealed[:-6], sealed[-6:]
    return head + ("A" if body[0] != "A" else "B") + body[1:]


@pytest.mark.parametrize("case", ["signature_of_another_token", "bad_source", "bad_holder", "wrong_key", "tampered",
                                  "plain_token"])
def test_a_redemption_that_is_not_elitea_cores_sealed_signed_request_is_refused(make, endpoint, custody_mod, case):
    module = make()
    if case == "signature_of_another_token":
        answer, _ = redeem(module, custody_mod, signed_sealed="s1.another")
    elif case == "bad_source":
        answer, _ = redeem(module, custody_mod, source="keycloak")
    elif case == "bad_holder":
        answer, _ = redeem(module, custody_mod, holder="mandate:not-a-uuid")
    elif case == "wrong_key":   # sealed with another key, signed with the right one
        answer, _ = redeem(module, custody_mod, seal_with="another-request-key-made-up-0123456789")
    else:
        nonce = secrets.token_urlsafe(16)
        good = custody_mod.seal(custody_mod.seal_key(REQUEST_KEY), OFFLINE_REFRESH_TOKEN,
                                custody_mod.seal_aad("redeem-req", TID, OID, HOLDER, nonce))
        sent = _tampered(good) if case == "tampered" else OFFLINE_REFRESH_TOKEN
        digest = hashlib.sha256(sent.encode()).hexdigest()
        answer = module.obo_offline_assertion(
            tid=TID, oid=OID, holder=HOLDER, source="login", sealed_refresh_token=sent,
            **signed_offline(("v1-offline", TID, OID, HOLDER, "login", digest), nonce=nonce))
    assert answer == {"ok": False, "code": "REQUEST_REFUSED"}
    assert endpoint.posts == []


def test_without_custody_configured_nothing_is_redeemed(make, endpoint, monkeypatch, custody_mod):
    module = make()
    monkeypatch.delenv("ELITEA_OBO_CUSTODY_KEY")
    assert redeem(module, custody_mod)[0] == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert redeem(make(obo_custody_enabled=False), custody_mod)[0] == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert endpoint.posts == []

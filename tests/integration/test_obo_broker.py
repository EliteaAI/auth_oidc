"""A Keycloak-brokered Microsoft sign-in kept for on-behalf-of exchanges (C-1009 #6754 step 4b).

Through the plugin's real login callback, logout and RPC; Redis, the realm's token and broker endpoints and the Entra
authority are fakes. Every token here is made up for the tests and never signed by anyone real.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import secrets
import time
import types
import urllib.parse

import pytest
import yaml

from conftest import CLIENT_ID, make_token

TID = "11111111-2222-3333-4444-555555555555"
OID = "oid-42"
API = "api-client"
REALM = "https://keycloak.example/realms/elitea"
BROKER_URL = f"{REALM}/broker/entra/token"
ENTRA = f"https://login.microsoftonline.com/{TID}/v2.0"
REQUEST_KEY = "custody-request-key-made-up-for-tests-0123"
WEB_SECRET = "web-client-secret-made-up-for-tests"
KC_REFRESH = "keycloak-refresh-token-made-up"
ENTRA_REFRESH = "entra-refresh-token-made-up-bbbb"
NEW_ENTRA_REFRESH = "entra-refresh-token-made-up-cccc"
KEY = f"c1009_obo_custody:{TID}:{OID}"
EXP = int(time.time()) + 3600


def jwt(**claims):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


KC_ACCESS = jwt(iss=REALM, sub="kc-user-1", typ="Bearer", tid=TID, oid=OID)   # the session's Keycloak access token
ENTRA_ACCESS = jwt(iss=ENTRA, ver="2.0", tid=TID, oid=OID, aud=API, scp="access_as_user", exp=EXP)
NEW_ENTRA_ACCESS = jwt(iss=ENTRA, ver="2.0", tid=TID, oid=OID, aud=API, scp="access_as_user", exp=EXP + 60)


def stored(**over):
    """What Keycloak's broker endpoint answers: the token response it stored at the brokered login."""
    body = {"access_token": ENTRA_ACCESS, "refresh_token": ENTRA_REFRESH, "id_token": "entra-id-token-made-up",
            "expires_in": 3599, "token_type": "Bearer", "scope": "api://elitea-api/access_as_user",
            "accessTokenExpiration": EXP}
    body.update(over)
    return {key: value for key, value in body.items() if value is not None}


class Redis:
    def __init__(self):
        self.values, self.ttls, self.calls = {}, {}, []

    def set(self, key, value, ex=None, keepttl=False, nx=False):
        if nx and key in self.values:
            return None
        if ":nonce:" not in key:
            self.calls.append(("set", key, ex, keepttl))
        self.values[key] = value
        if not keepttl:
            self.ttls[key] = ex
        return True

    def get(self, key):
        return self.values.get(key)

    def delete(self, key):
        self.calls.append(("delete", key))
        self.values.pop(key, None)


class Response:
    def __init__(self, status, chunks=(), headers=None, body=None):
        self.status_code, self.chunks, self.headers, self.body = status, list(chunks), headers or {}, body
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def iter_content(self, chunk_size=1):
        yield from self.chunks

    def json(self):
        return self.body


class Http:
    """The realm's broker endpoint (GET) and the Entra authority (POST), as the hardened session reaches them."""

    def __init__(self):
        self.gets, self.posts = [], []
        self.broker = (200, [json.dumps(stored()).encode()], {})
        self.refresh = (200, {"access_token": NEW_ENTRA_ACCESS, "refresh_token": NEW_ENTRA_REFRESH,
                              "expires_in": 3600})
        self.raise_on_get = None

    def session(self):
        return Session(self)


class Session:
    def __init__(self, http):
        self.http, self.trust_env, self.max_redirects, self.proxies = http, True, 30, None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _seen(self, kwargs):
        return {**kwargs, "_trust_env": self.trust_env, "_max_redirects": self.max_redirects, "_proxies": self.proxies}

    def get(self, url, **kwargs):
        self.http.gets.append((url, self._seen(kwargs)))
        if self.http.raise_on_get:
            raise self.http.raise_on_get
        status, chunks, headers = self.http.broker
        return Response(status, chunks, headers)

    def post(self, url, **kwargs):
        self.http.posts.append((url, self._seen(kwargs)))
        status, body = self.http.refresh
        return Response(status, body=body)


class LoginEndpoint:
    """Keycloak's token endpoint for the login's code exchange."""

    def __init__(self):
        self.posts, self.response = [], {}

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        response = self.response
        return types.SimpleNamespace(json=lambda: response, status_code=200)


class AppShim:
    def __init__(self, **proxied):
        self.__dict__["_proxied"] = proxied

    def __getattr__(self, name):
        if name in self._proxied:
            return self._proxied[name]
        raise RuntimeError("Not supported")


@pytest.fixture
def redis():
    return Redis()


@pytest.fixture
def http(monkeypatch, custody_mod):
    found = Http()
    monkeypatch.setattr(custody_mod, "requests", types.SimpleNamespace(Session=found.session))
    return found


@pytest.fixture
def login_endpoint(monkeypatch, login_mod):
    found = LoginEndpoint()
    monkeypatch.setattr(login_mod, "requests", types.SimpleNamespace(post=found.post))
    return found


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setenv("ELITEA_OBO_CUSTODY_KEY", REQUEST_KEY)
    monkeypatch.setenv("WEB_CLIENT_SECRET_FOR_TESTS", WEB_SECRET)


BROKERED = {
    "obo_custody_enabled": True, "obo_api_client_id": API, "obo_assertion_source": "keycloak_broker",
    "obo_broker_alias": "entra", "obo_broker_refresh_client_id": "web-client",
    "obo_broker_refresh_client_secret_env": "WEB_CLIENT_SECRET_FOR_TESTS",
    "obo_broker_refresh_scope": "openid profile email offline_access api://elitea-api/access_as_user",
}


@pytest.fixture
def make(build_module, signing_key, redis):
    def build(**config):
        for key, value in BROKERED.items():
            config.setdefault(key, value)
        config = {key: value for key, value in config.items() if value is not None}
        config.setdefault("token_endpoint", f"{REALM}/protocol/openid-connect/token")
        config.setdefault("scope", "openid profile email")
        module = build_module(jwt_public_key=signing_key.public_pem, issuer=config.pop("issuer", REALM), **config)
        module.context.app = AppShim(secret_key=module.context.app.secret_key,
                                     session_interface=types.SimpleNamespace(client=redis),
                                     config={"PERMANENT_SESSION_LIFETIME": "604800"})
        module.events = []
        module.context.event_manager = types.SimpleNamespace(
            fire_event=lambda name, payload: module.events.append((name, payload)))
        return module
    return build


def sign_in(module, flask, login_endpoint, signing_key, *, tid=TID, oid=OID, issuer=REALM, access=KC_ACCESS):
    """A login through Keycloak: the ID token is the realm's, with Entra's tid/oid mapped into it."""
    flask.request.args = {"target_to": "/"}
    _, url = module.login()
    sent = {key: values[0] for key, values in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()}
    login_endpoint.response = {
        "id_token": make_token(signing_key, nonce=sent["nonce"], iss=issuer, tid=tid, oid=oid, aud=CLIENT_ID),
        "access_token": access, "refresh_token": KC_REFRESH, "expires_in": 300, "token_type": "Bearer"}
    flask.request.method = "GET"
    flask.request.args = {"state": sent["state"], "code": "code-made-up"}
    return module.login_callback()


def signed(tid, oid, refresh=False):
    iat, nonce = int(time.time()), secrets.token_urlsafe(16)
    message = "|".join(("v1", tid, oid, "1" if refresh else "0", str(iat), nonce)).encode()
    return {"tid": tid, "oid": oid, "refresh": refresh, "iat": iat, "nonce": nonce,
            "signature": hmac.new(REQUEST_KEY.encode(), message, hashlib.sha256).hexdigest()}


def warnings(log):
    return [text for level, text, _ in log.records if level == "warning"]


SECRETS = (KC_ACCESS, KC_REFRESH, ENTRA_ACCESS, ENTRA_REFRESH, NEW_ENTRA_ACCESS, NEW_ENTRA_REFRESH, WEB_SECRET,
           "entra-id-token-made-up")


def assert_nothing_secret_logged(log):
    everything = log.everything()
    for secret in SECRETS:
        assert secret not in everything


# --- defaults --------------------------------------------------------------------------------------------------------

def test_the_shipped_config_sets_none_of_the_new_keys(plugin_root):
    shipped = yaml.safe_load(pathlib.Path(plugin_root, "config.yml").read_text()) or {}
    assert not {key for key in shipped if key.startswith("obo_")}   # every step-4/4b key stays commented out


def test_the_source_defaults_to_the_login_and_a_login_never_calls_the_broker(make, flask, login_endpoint, http,
                                                                             signing_key, redis):
    module = make(obo_assertion_source=None, issuer=ENTRA,
                  token_endpoint=f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token")
    assert module.obo_assertion_source() == "login"
    sign_in(module, flask, login_endpoint, signing_key, issuer=ENTRA, access=ENTRA_ACCESS)
    assert http.gets == [] and json.loads(redis.values[KEY])["assertion_source"] == "login"


# --- the broker call -------------------------------------------------------------------------------------------------

def test_a_brokered_sign_in_is_fetched_once_and_kept_as_the_same_record(make, flask, login_endpoint, http,
                                                                        signing_key, redis, log, auth_core):
    module = make()
    assert sign_in(module, flask, login_endpoint, signing_key)[0] == "SUCCESS"
    [(url, kwargs)] = http.gets
    assert url == BROKER_URL
    assert kwargs["headers"] == {"Authorization": f"Bearer {KC_ACCESS}", "Accept": "application/json"}
    assert not {"data", "json", "params"} & set(kwargs)                       # no body, no query
    assert (kwargs["allow_redirects"], kwargs["verify"], kwargs["stream"], kwargs["timeout"]) == (False, True, True,
                                                                                                    (3, 4))
    assert (kwargs["_trust_env"], kwargs["_max_redirects"], kwargs["_proxies"]) == (False, 0, {})
    record = json.loads(redis.values[KEY])
    assert record == {"issuer": REALM, "tid": TID, "oid": OID, "assertion_source": "broker",
                      "access_token": ENTRA_ACCESS, "refresh_token": ENTRA_REFRESH, "expires_at": EXP}
    assert redis.ttls[KEY] == 7 * 86400                                       # as long as the session lives
    assert auth_core.saved["provider_attr"]["delegation"]["access_token"] == KC_ACCESS   # the session as before
    assert warnings(log) == []
    assert_nothing_secret_logged(log)


def test_the_rpc_hands_the_brokered_assertion_to_main(make, flask, login_endpoint, http, signing_key):
    module = make()
    sign_in(module, flask, login_endpoint, signing_key)
    assert module.obo_assertion(**signed(TID, OID)) == {"ok": True, "assertion": ENTRA_ACCESS, "expires_at": EXP}


@pytest.mark.parametrize("access", [
    jwt(iss=ENTRA, ver="1.0", tid=TID, oid=OID, aud=API, exp=EXP),                       # a v1 token
    jwt(iss=f"https://sts.windows.net/{TID}/", ver="1.0", tid=TID, oid=OID, aud=API, exp=EXP),
    jwt(iss=ENTRA, ver="2.0", tid=TID, oid=OID, aud=f"api://{API}", exp=EXP),           # not the client id itself
    jwt(iss=ENTRA, ver="2.0", tid=TID, oid=OID, aud="https://graph.microsoft.com", exp=EXP),   # another API's
    jwt(iss=ENTRA, ver="2.0", tid=TID, oid="someone-else", aud=API, exp=EXP),            # another person's
    jwt(iss=ENTRA, ver="2.0", tid="99999999-2222-3333-4444-555555555555", oid=OID, aud=API, exp=EXP),
    jwt(iss="https://evil.example/v2.0", ver="2.0", tid=TID, oid=OID, aud=API, exp=EXP),
    "opaque-access-token", None,
])
def test_only_a_v2_token_of_the_person_for_the_platform_api_is_kept(make, flask, login_endpoint, http, signing_key,
                                                                    redis, log, access):
    http.broker = (200, [json.dumps(stored(access_token=access)).encode()], {})
    sign_in(make(), flask, login_endpoint, signing_key)
    assert redis.values == {}
    assert len(warnings(log)) == 1 and "not a v2 token of this person" in warnings(log)[0]
    assert_nothing_secret_logged(log)


@pytest.mark.parametrize("status, meaning", [
    (400, "not brokered, Store tokens is off"),          # a local (non-brokered) user, or Store tokens off
    (403, "read-token role"),                             # the role is not granted
    (404, "no token is stored"),
    (500, "unexpected answer"),
])
def test_a_refused_broker_call_keeps_nothing_and_warns_once_without_claims(make, flask, login_endpoint, http,
                                                                           signing_key, redis, log, status, meaning):
    http.broker = (status, [json.dumps({"error": "made-up", "user": "kc-user-1", "token": ENTRA_ACCESS}).encode()],
                   {"Location": f"https://evil.example/?t={ENTRA_REFRESH}"})
    assert sign_in(make(), flask, login_endpoint, signing_key)[0] == "SUCCESS"   # the login itself goes on
    assert redis.values == {}
    [line] = warnings(log)
    assert str(status) in line and meaning in line
    assert "kc-user-1" not in log.everything() and TID not in line and OID not in line
    assert_nothing_secret_logged(log)


def test_a_redirect_is_never_followed(make, flask, login_endpoint, http, signing_key, redis, log):
    http.broker = (302, [], {"Location": "https://evil.example/collect"})
    sign_in(make(), flask, login_endpoint, signing_key)
    [(_, kwargs)] = http.gets
    assert kwargs["allow_redirects"] is False and kwargs["_max_redirects"] == 0
    assert redis.values == {} and "302" in warnings(log)[0]


@pytest.mark.parametrize("chunks", [
    [b"x" * 70_000],                       # larger than a token response can be
    [b"not json"],
    [json.dumps([ENTRA_ACCESS, ENTRA_REFRESH]).encode()],   # JSON, but no token response (and never logged)
])
def test_an_oversized_or_malformed_answer_keeps_nothing(make, flask, login_endpoint, http, signing_key, redis, log,
                                                         chunks):
    http.broker = (200, chunks, {})
    sign_in(make(), flask, login_endpoint, signing_key)
    assert redis.values == {} and "no token response" in warnings(log)[0]
    assert_nothing_secret_logged(log)


def test_a_slow_answer_is_cut_at_the_total_time_budget(make, flask, login_endpoint, http, signing_key, redis, log,
                                                       monkeypatch, custody_mod):
    monkeypatch.setattr(custody_mod, "BROKER_TOTAL_S", -1)   # the budget is spent before the first chunk arrives
    sign_in(make(), flask, login_endpoint, signing_key)
    assert redis.values == {} and "too slow" in warnings(log)[0]


def test_a_failing_broker_call_keeps_nothing_and_logs_only_the_exception_type(make, flask, login_endpoint, http,
                                                                              signing_key, redis, log):
    http.raise_on_get = TimeoutError(f"read timed out for {KC_ACCESS}")
    sign_in(make(), flask, login_endpoint, signing_key)
    assert redis.values == {} and warnings(log) == ["OBO custody was not kept: the broker token endpoint failed "
                                                    "(TimeoutError)"]
    assert_nothing_secret_logged(log)


def test_a_keycloak_identity_that_differs_from_the_entra_token_keeps_nothing(make, flask, login_endpoint, http,
                                                                             signing_key, redis):
    sign_in(make(), flask, login_endpoint, signing_key, oid="someone-else")   # realm maps another oid than Entra's
    assert redis.values == {} and not any(KEY.rsplit(":", 1)[0] in key for key in redis.values)


def test_only_a_login_verified_against_the_configured_realm_is_brokered(make, http, redis):
    module = make()
    identity = {"issuer": "https://other.example/realms/elitea", "tid": TID, "oid": OID, "sub": "kc-user-1"}
    assert module.keep_obo_custody(identity, {"access_token": KC_ACCESS}) is False
    assert http.gets == [] and redis.values == {}


def test_a_local_user_without_entra_claims_is_never_brokered(make, flask, login_endpoint, http, signing_key, redis):
    sign_in(make(), flask, login_endpoint, signing_key, tid=None, oid=None)
    assert http.gets == [] and redis.values == {}


# --- configuration fails closed --------------------------------------------------------------------------------------

@pytest.mark.parametrize("config", [
    {"obo_assertion_source": "keycloak"},                                  # not a known source
    {"obo_broker_alias": None},
    {"obo_broker_alias": "../admin"},
    {"obo_broker_alias": "entra/token?x="},
    {"issuer": "http://keycloak.example/realms/elitea"},                   # plain http to a real host
    {"issuer": "http://keycloak.localhost:8082/realms/elitea"},            # http without the dev flag
    {"issuer": "https://user:pw@keycloak.example/realms/elitea"},
    {"issuer": "https://keycloak.example/realms/elitea?x=1"},
])
def test_a_broker_configuration_that_cannot_be_trusted_keeps_nothing_and_says_so(make, flask, login_endpoint, http,
                                                                                  signing_key, redis, log, config):
    module = make(**config)
    log.clear()
    assert module.check_obo_custody_config() is False
    assert any(level == "error" and "OBO custody is enabled" in text for level, text, _ in log.records)
    if "issuer" not in config:
        sign_in(module, flask, login_endpoint, signing_key)
        assert http.gets == [] and redis.values == {}


def test_http_is_accepted_for_a_localhost_realm_with_the_dev_flag_only(make):
    local = "http://keycloak.localhost:8082/realms/elitea"
    assert make(issuer=local, obo_broker_insecure_dev_http=True).obo_broker_url() == f"{local}/broker/entra/token"
    assert make(issuer=local, obo_broker_insecure_dev_http="true").obo_broker_url() is None   # an explicit true only
    assert make(issuer="http://keycloak.example/realms/elitea", obo_broker_insecure_dev_http=True).obo_broker_url() \
        is None


def test_a_complete_broker_configuration_passes_the_init_check(make, log):
    assert make().check_obo_custody_config() is True and warnings(log) == []


def test_without_a_refresh_client_the_init_check_passes_and_warns(make, log):
    assert make(obo_broker_refresh_client_id=None).check_obo_custody_config() is True
    assert len(warnings(log)) == 1 and "no refresh client" in warnings(log)[0]


# --- refresh and logout -----------------------------------------------------------------------------------------------

def test_a_brokered_record_is_refreshed_at_the_entra_authority_with_the_web_client(make, flask, login_endpoint, http,
                                                                                   signing_key, redis, log):
    module = make()
    sign_in(module, flask, login_endpoint, signing_key)
    answer = module.obo_assertion(**signed(TID, OID, refresh=True))
    assert answer["ok"] is True and answer["assertion"] == NEW_ENTRA_ACCESS
    [(url, kwargs)] = http.posts
    assert url == f"https://login.microsoftonline.com/{TID}/oauth2/v2.0/token"   # never Keycloak's token endpoint
    assert kwargs["data"] == {"grant_type": "refresh_token", "refresh_token": ENTRA_REFRESH,
                              "scope": BROKERED["obo_broker_refresh_scope"], "client_id": "web-client",
                              "client_secret": WEB_SECRET}
    assert (kwargs["auth"], kwargs["allow_redirects"], kwargs["verify"], kwargs["timeout"], kwargs["_trust_env"],
            kwargs["_max_redirects"], kwargs["_proxies"]) == (None, False, True, 4, False, 0, {})
    record = json.loads(redis.values[KEY])
    assert (record["assertion_source"], record["refresh_token"]) == ("broker", NEW_ENTRA_REFRESH)
    assert redis.calls[-1] == ("set", KEY, None, True)                          # the custody lifetime is kept
    assert_nothing_secret_logged(log)


@pytest.mark.parametrize("change", [
    {"obo_broker_refresh_client_id": None}, {"obo_broker_refresh_client_secret_env": "UNSET_FOR_TESTS"},
    {"obo_broker_refresh_scope": None}])
def test_without_a_complete_refresh_client_a_brokered_record_is_not_refreshed(make, flask, login_endpoint, http,
                                                                              signing_key, redis, change):
    module = make(**change)
    sign_in(module, flask, login_endpoint, signing_key)
    assert module.obo_assertion(**signed(TID, OID, refresh=True)) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert http.posts == [] and json.loads(redis.values[KEY])["access_token"] == ENTRA_ACCESS


@pytest.mark.parametrize("refreshed", [
    {"access_token": jwt(iss=ENTRA, ver="1.0", tid=TID, oid=OID, aud=API), "expires_in": 3600},
    {"access_token": jwt(iss=ENTRA, ver="2.0", tid=TID, oid="someone-else", aud=API), "expires_in": 3600}])
def test_a_refreshed_brokered_token_is_held_to_the_same_checks(make, flask, login_endpoint, http, signing_key, redis,
                                                               refreshed):
    module = make()
    sign_in(module, flask, login_endpoint, signing_key)
    http.refresh = (200, refreshed)
    assert module.obo_assertion(**signed(TID, OID, refresh=True)) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}
    assert json.loads(redis.values[KEY])["access_token"] == ENTRA_ACCESS


def test_a_brokered_record_with_a_tenant_that_is_no_guid_is_never_refreshed(make, redis):
    module = make()
    record = {"tid": "../x", "oid": OID, "assertion_source": "broker", "refresh_token": ENTRA_REFRESH}
    assert module.refresh_obo_custody(record) is None


def test_signing_out_drops_the_brokered_custody(make, flask, login_endpoint, http, signing_key, redis, auth_core):
    module = make(logout_mode="local", end_session_endpoint=f"{REALM}/protocol/openid-connect/logout")
    sign_in(module, flask, login_endpoint, signing_key)
    auth_core.context = auth_core.saved
    auth_core.logout_success_redirect = lambda target: ("LOGGED_OUT", target)
    flask.request.args = {}
    assert module.logout()[0] == "LOGGED_OUT"
    assert KEY not in redis.values
    assert module.events == [("auth_oidc_obo_custody_dropped", {"tid": TID, "oid": OID})]
    assert module.obo_assertion(**signed(TID, OID)) == {"ok": False, "code": "ASSERTION_UNAVAILABLE"}


def test_the_login_source_still_refuses_a_keycloak_issuer(make, flask, login_endpoint, http, signing_key, redis):
    """Step 4 unchanged: with the default source a realm login keeps nothing and asks the realm for nothing."""
    module = make(obo_assertion_source="login")
    sign_in(module, flask, login_endpoint, signing_key)
    assert http.gets == [] and redis.values == {}


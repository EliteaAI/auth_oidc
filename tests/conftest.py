"""Shared fixtures. Mirrors the runtime shape of the auth_oidc module."""
import pathlib
import sys
import time
import types

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

TESTS_DIR = pathlib.Path(__file__).resolve().parent
PLUGIN_ROOT = TESTS_DIR.parent

sys.path.insert(0, str(TESTS_DIR))

from fixtures import helpers  # noqa: E402  pylint: disable=C0413

LOG = helpers.install_pylon_stubs()

CLIENT_ID = "client-1"
ISSUER = "https://login.example.com/tenant-1/v2.0"
TID = "tenant-1"
OID = "object-1"
JWKS_URI = "https://login.example.com/tenant-1/keys"
SECRET_KEY = "test-secret-key-" + "0" * 48


@pytest.fixture(scope="session")
def plugin_root() -> pathlib.Path:
    return PLUGIN_ROOT


@pytest.fixture(scope="session")
def module_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "module")


@pytest.fixture(scope="session")
def jwt_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "methods.jwt")


@pytest.fixture(scope="session")
def tools_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "methods.tools")


@pytest.fixture(scope="session")
def id_token_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "methods.id_token")


@pytest.fixture(scope="session")
def login_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "routes.login")


@pytest.fixture(autouse=True)
def runtime():
    """Fresh log, session, request and auth_core for every test."""
    helpers.reset_runtime()


@pytest.fixture
def log():
    return LOG


@pytest.fixture
def auth_core():
    return helpers.AUTH_CORE


@pytest.fixture
def flask():
    return helpers.FLASK


# --- keys and tokens ---------------------------------------------------------


class KeyPair:
    def __init__(self, private_key):
        self.private_key = private_key
        self.private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def jwk(self, kid):
        algorithm = jwt.algorithms.RSAAlgorithm \
            if isinstance(self.private_key, rsa.RSAPrivateKey) \
            else jwt.algorithms.ECAlgorithm
        data = algorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        return {**data, "kid": kid, "use": "sig"}


@pytest.fixture(scope="session")
def signing_key():
    return KeyPair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def other_key():
    return KeyPair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def ec_key():
    return KeyPair(ec.generate_private_key(ec.SECP256R1()))


def claims(**overrides):
    """A valid ID token payload; a None override removes the claim."""
    now = int(time.time())
    data = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "sub-1",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "nonce": "nonce-1",
        "tid": TID,
        "oid": OID,
        "email": "user@example.com",
        "preferred_username": "user@example.com",
    }
    data.update(overrides)
    return {key: value for key, value in data.items() if value is not None}


def make_token(key, kid="kid-1", algorithm="RS256", **overrides):
    return jwt.encode(
        claims(**overrides), key.private_pem, algorithm=algorithm,
        headers={"kid": kid},
    )


# --- the module under test ---------------------------------------------------


class Descriptor:
    def __init__(self, config):
        self.config = config
        self.name = "auth_oidc"
        self.initialized = False

    def init_methods(self, module_methods=True):
        self.methods_initialized = True

    def init_all(self, **kwargs):
        self.initialized = True

    def deinit_all(self):
        pass

    def render_template(self, name, **kwargs):
        return ("TEMPLATE", name, kwargs)


@pytest.fixture(scope="session")
def custody_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "methods.obo_custody")


@pytest.fixture(scope="session")
def custody_rpc_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "rpc.obo_custody")


@pytest.fixture(scope="session")
def logout_mod(plugin_root):
    return helpers.import_plugin_module(plugin_root, "routes.logout")


@pytest.fixture
def build_module(module_mod, jwt_mod, tools_mod, id_token_mod, login_mod, custody_mod, custody_rpc_mod, logout_mod):
    """An auth_oidc module bound to a config, with every Method/Route mixed in.

    Pylon merges every methods/*.py and routes/*.py class onto the one Module
    instance, so the same is done here. Initialisers run as pylon runs them.
    """
    class Subject(
            module_mod.Module, jwt_mod.Method, tools_mod.Method,
            id_token_mod.Method, login_mod.Route, logout_mod.Route, custody_mod.Method, custody_rpc_mod.RPC,
    ):
        pass

    def build(**config):
        config.setdefault("client_id", CLIENT_ID)
        config.setdefault("client_secret", "client-secret")
        config.setdefault("authorization_endpoint", "https://login.example.com/authorize")
        config.setdefault("token_endpoint", "https://login.example.com/token")
        config.setdefault("login_mode", "get")
        descriptor = Descriptor(config)
        context = types.SimpleNamespace(app=types.SimpleNamespace(secret_key=SECRET_KEY))
        subject = Subject(context, descriptor)
        subject._init()  # methods/jwt.py
        subject._id_token_init()  # methods/id_token.py
        return subject

    return build


def pytest_collection_modifyitems(items):
    for item in items:
        if "/unit/" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

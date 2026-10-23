"""Helpers for importing auth_oidc modules outside the Pylon runtime."""
import importlib
import pathlib
import sys
import types
from typing import Any

# auth_oidc/__init__.py imports .module, which pulls in the whole Pylon runtime.
# Tests therefore never import the real package: they register a synthetic one
# whose __path__ points at the plugin directory, so the modules under test load
# from the real files without __init__ running.
PACKAGE_NAME = "auth_oidc_under_test"

SUBPACKAGES = ("methods", "routes")


class Log:
    """Pylon's log, recording everything the plugin chose to say.

    Both the formatted line and the raw arguments are kept: a secret passed as a
    format argument is a leak even when the format string never prints it.
    """

    def __init__(self):
        self.records = []

    def clear(self):
        self.records.clear()

    def _add(self, level, message, args):
        try:
            text = message % args if args else str(message)
        except (TypeError, ValueError):
            text = str(message)
        self.records.append((level, text, tuple(repr(arg) for arg in args)))

    def lines(self, level=None):
        return [text for lvl, text, _ in self.records if level in (None, lvl)]

    def everything(self):
        """All text the plugin logged, formatted lines and raw arguments."""
        parts = []
        for _, text, raw in self.records:
            parts.append(text)
            parts.extend(raw)
        return "\n".join(parts)

    def debug(self, message, *args, **kwargs):
        self._add("debug", message, args)

    def info(self, message, *args, **kwargs):
        self._add("info", message, args)

    def warning(self, message, *args, **kwargs):
        self._add("warning", message, args)

    def error(self, message, *args, **kwargs):
        self._add("error", message, args)

    def exception(self, message, *args, **kwargs):
        self._add("exception", message, args)

    def critical(self, message, *args, **kwargs):
        self._add("critical", message, args)


class FakeAuthCore:
    """The auth_core tool: the context the plugin reads and writes, and the replies."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.context = {"provider_attr": {}}
        self.saved = None
        self.registered = []
        self.unregistered = []

    def get_auth_context(self):
        return self.context

    def set_auth_context(self, auth_ctx):
        self.saved = auth_ctx

    def access_denied_reply(self):
        return "DENIED"

    def access_success_redirect(self, target_token):
        return ("SUCCESS", target_token)

    def get_user_from_provider(self, name):
        raise RuntimeError("no such user")

    def get_relative_url_prefix(self, descriptor, prefix=None):
        return prefix

    def register_auth_provider(self, name, **kwargs):
        self.registered.append(name)

    def unregister_auth_provider(self, name):
        self.unregistered.append(name)


class Session(dict):
    """flask.session: a dict that also carries the `modified` flag."""

    modified = False


LOG = Log()
AUTH_CORE = FakeAuthCore()
FLASK = types.ModuleType("flask")


def _reset_flask():
    FLASK.session = Session()
    FLASK.request = types.SimpleNamespace(method="GET", args={}, form={}, host_url="http://localhost/")
    FLASK.redirect = lambda url: ("REDIRECT", url)
    FLASK.url_for = lambda endpoint, **kwargs: f"/{endpoint}"


def reset_runtime() -> None:
    """Fresh log, session, request and auth_core for the next test."""
    LOG.clear()
    AUTH_CORE.reset()
    _reset_flask()


def install_pylon_stubs() -> Log:
    """Register the import surface auth_oidc's modules need: pylon, tools, flask."""
    pylon = sys.modules.get("pylon") or types.ModuleType("pylon")
    pylon_core = sys.modules.get("pylon.core") or types.ModuleType("pylon.core")
    pylon_core_tools = types.ModuleType("pylon.core.tools")

    def decorator(*args, **kwargs):
        return lambda func: func

    pylon_core_tools.log = LOG
    pylon_core_tools.web = types.SimpleNamespace(
        method=decorator, init=decorator, route=decorator, rpc=decorator,
    )
    pylon_core_tools.module = types.SimpleNamespace(ModuleModel=object)

    pylon.core = pylon_core
    pylon_core.tools = pylon_core_tools

    sys.modules["pylon"] = pylon
    sys.modules["pylon.core"] = pylon_core
    sys.modules["pylon.core.tools"] = pylon_core_tools

    # from tools import auth_core - one stable recorder, reset per test.
    tools = types.ModuleType("tools")
    tools.auth_core = AUTH_CORE
    sys.modules["tools"] = tools

    # flask is not a test dependency; the plugin only needs session, request,
    # redirect and url_for.
    _reset_flask()
    sys.modules["flask"] = FLASK

    return LOG


def register_plugin_package(plugin_root: pathlib.Path) -> None:
    """Map PACKAGE_NAME onto the plugin directory without executing __init__."""
    if PACKAGE_NAME in sys.modules:
        return

    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(plugin_root)]
    sys.modules[PACKAGE_NAME] = package

    for name in SUBPACKAGES:
        subpackage = types.ModuleType(f"{PACKAGE_NAME}.{name}")
        subpackage.__path__ = [str(plugin_root / name)]
        sys.modules[f"{PACKAGE_NAME}.{name}"] = subpackage
        setattr(package, name, subpackage)


def import_plugin_module(plugin_root: pathlib.Path, dotted: str) -> Any:
    """Import e.g. "routes.login" from the plugin."""
    register_plugin_package(plugin_root)

    return importlib.import_module(f"{PACKAGE_NAME}.{dotted}")

#!/usr/bin/env python3
"""Check that a Keycloak realm is set up for Elitea's on-behalf-of access through a brokered Entra login.

C-1009 #6754 step 4b (runbook: RUNBOOK.md next to this file). Run it against the overlay's import file or against an
export of the organisation realm (Realm settings -> Action -> Partial export with groups, roles and clients, or
kc.sh export). It reads the file only and prints one line per check, never a value of a secret. Exit code 0 when every
check passes, 1 otherwise.

    python3 check_realm.py realm.json --template     # an import file whose ids are ${...} placeholders
    python3 check_realm.py realm-export.json --alias entra --client elitea-web --tenant <Entra tenant id>

Elitea takes the person's Entra identity from the claims tid/oid of the realm's tokens, and Keycloak hands the stored
Entra token to any token that carries broker read-token. So the check fails on anything else that could put tid/oid
into Elitea's tokens or write the two attributes behind them, and on any way read-token reaches a token other than
Elitea's client's.
"""

import argparse
import json
import re
import sys

PROFILE_COMPONENT = "org.keycloak.userprofile.UserProfileProvider"
ATTRIBUTE_IMPORTER = "oidc-user-attribute-idp-mapper"
ATTRIBUTE_MAPPER = "oidc-usermodel-attribute-mapper"
HARDCODED_ROLE = "oidc-hardcoded-role-mapper"
READ_TOKEN = "broker.read-token"
_ENTRA_V2 = re.compile(r"^https://login\.microsoftonline\.com/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/v2\.0/?$")
_PLACEHOLDER_V2 = re.compile(r"^https://login\.microsoftonline\.com/(\$\{[A-Z0-9_]+\})/v2\.0/?$")


def _true(value):
    return value is True or value == "true"


def _values(config):
    """Every string of a mapper/component config (Keycloak stores some as one-element lists)."""
    for value in (config or {}).values():
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str):
                yield item


def _walk_components(components, skip):
    """Every component and sub-component of the realm (user federation, its mappers, ...) except ``skip``."""
    for kind, items in (components or {}).items():
        if kind == skip:
            continue
        for item in items or []:
            yield kind, item
            yield from _walk_components(item.get("subComponents"), skip)


def _reachable_mappers(realm, client):
    """Protocol mappers that can reach the client's tokens: its own, those of its default and optional client scopes,
    and those of the realm's default scopes. Also the names of referenced scopes the file does not contain."""
    scopes = {scope.get("name"): scope for scope in realm.get("clientScopes") or []}
    names = set(client.get("defaultClientScopes") or []) | set(client.get("optionalClientScopes") or []) | \
        set(realm.get("defaultDefaultClientScopes") or []) | set(realm.get("defaultOptionalClientScopes") or [])
    found = [("client", mapper) for mapper in client.get("protocolMappers") or []]
    for name in sorted(names & set(scopes)):
        found += [(f"scope {name}", mapper) for mapper in scopes[name].get("protocolMappers") or []]
    return found, sorted(names - set(scopes))


def _profile_attributes(realm):
    for component in (realm.get("components") or {}).get(PROFILE_COMPONENT) or []:
        for raw in (component.get("config") or {}).get("kc.user.profile.config") or []:
            try:
                return {item.get("name"): item for item in json.loads(raw).get("attributes") or []}
            except (TypeError, ValueError, AttributeError):
                return None
    return None


def _grants_read_token(roles):
    """Does a role-mapping block ({"client": {"broker": [...]}} or {"broker": [...]}) hold broker read-token?"""
    client = roles.get("client") if isinstance(roles.get("client"), dict) else roles
    return "read-token" in ((client or {}).get("broker") or [])


def checks(realm, alias, client_id, tid_claim, oid_claim, tenant=None,  # pylint: disable=R0912,R0913,R0914,R0915
           template=False):
    """``[(name, ok)]`` for the realm."""
    results = []
    idp = next((item for item in realm.get("identityProviders") or [] if item.get("alias") == alias), None)
    config = (idp or {}).get("config") or {}
    issuer = _ENTRA_V2.match(config.get("issuer") or "") or \
        (_PLACEHOLDER_V2.match(config.get("issuer") or "") if template and tenant is None else None)
    scopes = (config.get("defaultScope") or "").split()
    results += [
        (f"identity provider '{alias}' exists, is enabled and generic OIDC",
         bool(idp) and idp.get("enabled") is not False and idp.get("providerId") == "oidc"),
        ("Store tokens is on (storeToken)", bool(idp) and idp.get("storeToken") is True),
        ("Stored tokens readable is off (read-token comes from Elitea's client only)",
         bool(idp) and idp.get("addReadTokenRoleOnCreate") is not True),
        ("issuer is the Entra v2 issuer of one tenant (no common/organizations)" +
         (" and of the given tenant" if tenant else ""),
         bool(issuer) and (tenant is None or issuer.group(1).lower() == tenant.lower())),
        ("signature validated with the tenant JWKS",
         _true(config.get("validateSignature")) and _true(config.get("useJwksUrl")) and
         (config.get("jwksUrl") or "").startswith("https://login.microsoftonline.com/")),
        ("PKCE on (S256)", _true(config.get("pkceEnabled")) and config.get("pkceMethod") == "S256"),
        ("user info not called (the access token is for the platform API, not Graph)",
         _true(config.get("disableUserInfo")) or not config.get("userInfoUrl")),
        ("default scopes ask for openid, offline_access and the platform API's access_as_user",
         "openid" in scopes and "offline_access" in scopes and
         any(scope.startswith("api://") and scope.endswith("/access_as_user") for scope in scopes)),
    ]

    # who writes the two attributes behind the identity: the two importers of this provider, nothing else
    expected_writers = {"tid": None, "oid": None}
    other_writers = []
    for mapper in realm.get("identityProviderMappers") or []:
        mconfig = mapper.get("config") or {}
        if mapper.get("identityProviderAlias") == alias and mapper.get("identityProviderMapper") == ATTRIBUTE_IMPORTER \
                and mconfig.get("claim") in expected_writers and expected_writers[mconfig["claim"]] is None:
            expected_writers[mconfig["claim"]] = (mconfig.get("user.attribute"), mconfig.get("syncMode"), mapper)
    attributes = {claim: (found or (None,))[0] for claim, found in expected_writers.items()}
    for mapper in realm.get("identityProviderMappers") or []:
        if any(found and mapper is found[2] for found in expected_writers.values()):
            continue
        if set(_values(mapper.get("config"))) & {value for value in attributes.values() if value}:
            other_writers.append(mapper.get("name"))
    federation = [item.get("name") for _, item in _walk_components(realm.get("components"), PROFILE_COMPONENT)
                  if set(_values(item.get("config"))) & {value for value in attributes.values() if value}]
    email = [m for m in realm.get("identityProviderMappers") or [] if m.get("identityProviderAlias") == alias and
             (m.get("config") or {}).get("claim") == "email" and
             (m.get("config") or {}).get("user.attribute") == "email"]
    results += [
        ("IdP mapper: Entra tid -> a user attribute, synced at every login (FORCE)",
         bool(attributes["tid"]) and expected_writers["tid"][1] == "FORCE"),
        ("IdP mapper: Entra oid -> a user attribute, synced at every login (FORCE)",
         bool(attributes["oid"]) and expected_writers["oid"][1] == "FORCE"),
        ("IdP mapper: email -> email", bool(email)),
        ("no other identity-provider mapper writes the two identity attributes", not other_writers),
        ("no user federation (LDAP, ...) mapper writes the two identity attributes", not federation),
    ]

    # what reaches Elitea's tokens: exactly one source per identity claim
    client = next((item for item in realm.get("clients") or [] if item.get("clientId") == client_id), None)
    reachable, missing = _reachable_mappers(realm, client or {})
    results += [(f"client '{client_id}' exists", bool(client)),
                ("every client scope the client's tokens can get is in the file", not missing)]
    for claim, attribute in ((tid_claim, attributes["tid"]), (oid_claim, attributes["oid"])):
        emitting = [mapper for _, mapper in reachable if (mapper.get("config") or {}).get("claim.name") == claim]
        only = emitting[0] if len(emitting) == 1 else {}
        oconfig = only.get("config") or {}
        results.append((f"exactly one mapper puts claim '{claim}' into the client's tokens (own, default, optional and "
                        f"realm-default scopes), from the {claim} attribute, in ID and access token",
                        bool(attribute) and only.get("protocolMapper") == ATTRIBUTE_MAPPER and
                        oconfig.get("user.attribute") == attribute and _true(oconfig.get("id.token.claim")) and
                        _true(oconfig.get("access.token.claim"))))
    scripts = [mapper.get("name") for _, mapper in reachable if "script" in (mapper.get("protocolMapper") or "")]
    results.append(("no script mapper reaches the client's tokens", not scripts))

    # broker read-token: only in Elitea's client's tokens, held by nobody
    own = [mapper for mapper in (client or {}).get("protocolMappers") or []
           if mapper.get("protocolMapper") == HARDCODED_ROLE and (mapper.get("config") or {}).get("role") == READ_TOKEN]
    elsewhere = [item.get("clientId") for item in realm.get("clients") or [] if item is not client and any(
        mapper.get("protocolMapper") == HARDCODED_ROLE and READ_TOKEN in _values(mapper.get("config"))
        for mapper in item.get("protocolMappers") or [])]
    elsewhere += [f"scope {scope.get('name')}" for scope in realm.get("clientScopes") or [] if any(
        READ_TOKEN in _values(mapper.get("config")) for mapper in scope.get("protocolMappers") or [])]
    holders = [role.get("name") for kind in ("realm",) for role in ((realm.get("roles") or {}).get(kind) or [])
               if _grants_read_token(role.get("composites") or {})]
    holders += [f"client role {role.get('name')}" for roles in ((realm.get("roles") or {}).get("client") or {}).values()
                for role in roles or [] if _grants_read_token(role.get("composites") or {})]
    holders += [f"group {group.get('name')}" for group in realm.get("groups") or []
                if _grants_read_token({"client": group.get("clientRoles") or {}})]
    holders += [f"user {user.get('username')}" for user in realm.get("users") or []
                if _grants_read_token({"client": user.get("clientRoles") or {}})]
    results += [
        ("Elitea's client tokens carry broker read-token (a hardcoded role mapper on the client itself)", bool(own)),
        ("no other client or client scope adds broker read-token", not elsewhere),
        ("no role, group or user holds broker read-token (so no other client's token can carry it)", not holders),
    ]

    profile = _profile_attributes(realm)
    for attribute in (attributes["tid"], attributes["oid"]):
        if not attribute:
            continue
        declared = (profile or {}).get(attribute)
        edit = ((declared or {}).get("permissions") or {}).get("edit") or []
        results.append((f"user profile declares '{attribute}', editable by admins only (users cannot change it)",
                        bool(declared) and "user" not in edit))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("realm_file")
    parser.add_argument("--alias", default="entra", help="identity provider alias (default entra)")
    parser.add_argument("--client", default="elitea-web-local", help="Elitea's client id in the realm")
    parser.add_argument("--tid-claim", default="tid", help="token claim carrying the Entra tenant id")
    parser.add_argument("--oid-claim", default="oid", help="token claim carrying the Entra object id")
    parser.add_argument("--tenant", help="the Entra tenant id the identity provider must be bound to")
    parser.add_argument("--template", action="store_true",
                        help="an import file: the tenant in the issuer may be a ${NAME} placeholder Keycloak resolves")
    args = parser.parse_args(argv)
    with open(args.realm_file, encoding="utf-8") as handle:
        realm = json.load(handle)
    results = checks(realm, args.alias, args.client, args.tid_claim, args.oid_claim, args.tenant, args.template)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    failed = sum(1 for _, ok in results if not ok)
    print(f"{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

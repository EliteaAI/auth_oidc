"""The realm check DevOps runs before the brokered sign-in is trusted (docs/keycloak-broker/check_realm.py, #6754 4b).

The example realm passes; every deliberately broken copy fails the check that guards it (and only realms that pass
may be listed in elitea_core's entra_obo_broker_issuers). The realms are made-up fixtures, no real ids.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

DOCS = pathlib.Path(__file__).resolve().parents[2] / "docs" / "keycloak-broker"
TENANT = "00000000-0000-4000-8000-000000000001"


@pytest.fixture(scope="module")
def check():
    spec = importlib.util.spec_from_file_location("check_realm_under_test", DOCS / "check_realm.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def realm():
    return json.loads((DOCS / "realm-example.json").read_text())


def exported(realm):
    """The example as an export looks: ids resolved, the built-in client scopes listed and referenced."""
    found = copy.deepcopy(realm)
    config = found["identityProviders"][0]["config"]
    for key in ("issuer", "authorizationUrl", "tokenUrl", "jwksUrl", "logoutUrl"):
        config[key] = config[key].replace("${KC_ENTRA_TENANT_ID}", TENANT)
    found["clientScopes"] = [
        {"name": "profile", "protocolMappers": [{
            "name": "family name", "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {"user.attribute": "lastName", "claim.name": "family_name"}}]},
        {"name": "roles", "protocolMappers": [{
            "name": "client roles", "protocolMapper": "oidc-usermodel-client-role-mapper",
            "config": {"claim.name": "resource_access.${client_id}.roles"}}]},
        {"name": "phone", "protocolMappers": []},
    ]
    found["clients"][0]["defaultClientScopes"] = ["profile", "roles"]
    found["clients"][0]["optionalClientScopes"] = ["phone"]
    found["clients"].append({"clientId": "another-app", "protocolMappers": []})
    found["defaultDefaultClientScopes"] = ["profile", "roles"]
    return found


def failed(check, realm, **kwargs):
    kwargs.setdefault("template", "${" in json.dumps(realm["identityProviders"]))
    return [name for name, ok in check.checks(realm, "entra", "elitea-web-local", "tid", "oid", **kwargs) if not ok]


def test_the_example_realm_and_its_export_pass(check, realm):
    assert failed(check, realm) == []
    assert failed(check, exported(realm)) == [] and failed(check, exported(realm), tenant=TENANT) == []


def test_the_command_line_exits_non_zero_on_a_broken_realm(check, realm, tmp_path, capsys):
    good, bad = tmp_path / "good.json", tmp_path / "bad.json"
    good.write_text(json.dumps(realm))
    realm["identityProviders"][0]["storeToken"] = False
    bad.write_text(json.dumps(realm))
    assert check.main([str(good), "--template"]) == 0 and check.main([str(bad), "--template"]) == 1
    assert "clientSecret" not in capsys.readouterr().out


def second_tid_mapper(realm):      # B1: a second mapper fills tid from an attribute people can edit
    realm["clients"][0]["protocolMappers"].append({
        "name": "tid again", "protocolMapper": "oidc-usermodel-attribute-mapper",
        "config": {"user.attribute": "locale", "claim.name": "tid"}})


def hardcoded_oid_in_optional_scope(realm):   # B1: an optional scope a person can ask for emits oid
    realm["clientScopes"].append({"name": "who", "protocolMappers": [{"name": "fixed oid",
                                  "protocolMapper": "oidc-hardcoded-claim-mapper",
                                  "config": {"claim.name": "oid", "claim.value": "someone-else"}}]})
    realm["clients"][0]["optionalClientScopes"].append("who")


def oid_in_realm_default_scope(realm):        # B1: a realm default scope emits oid
    realm["clientScopes"].append({"name": "realm-wide", "protocolMappers": [{"name": "oid",
                                  "protocolMapper": "oidc-usermodel-attribute-mapper",
                                  "config": {"user.attribute": "nickname", "claim.name": "oid"}}]})
    realm["defaultDefaultClientScopes"].append("realm-wide")


def referenced_scope_missing(realm):          # B1: a scope the check cannot see
    realm["clients"][0]["optionalClientScopes"].append("not-in-the-file")


def script_mapper(realm):                     # B1: a script can emit any claim
    realm["clients"][0]["protocolMappers"].append({"name": "js", "protocolMapper": "oidc-script-based-protocol-mapper",
                                                    "config": {"claim.name": "extra"}})


def other_idp_writes_oid(realm):              # B1: another identity provider writes the identity attribute
    realm["identityProviderMappers"].append({"name": "social oid", "identityProviderAlias": "github",
                                             "identityProviderMapper": "oidc-user-attribute-idp-mapper",
                                             "config": {"claim": "id", "user.attribute": "entra_oid"}})


def same_idp_hardcodes_tid(realm):            # B1: a second mapper of the same provider writes it
    realm["identityProviderMappers"].append({"name": "fixed tid", "identityProviderAlias": "entra",
                                             "identityProviderMapper": "hardcoded-attribute-idp-mapper",
                                             "config": {"attribute": "entra_tid", "attribute.value": "x"}})


def ldap_writes_tid(realm):                   # B1: user federation writes the identity attribute
    realm["components"]["org.keycloak.storage.UserStorageProvider"] = [{"name": "ldap", "providerId": "ldap",
        "subComponents": {"org.keycloak.storage.ldap.mappers.LDAPStorageMapper": [
            {"name": "tid", "providerId": "user-attribute-ldap-mapper",
             "config": {"user.model.attribute": ["entra_tid"], "ldap.attribute": ["extensionAttribute1"]}}]}}]


def read_token_in_default_role(realm):        # B2: the role every user holds
    realm["roles"] = {"realm": [{"name": "default-roles-elitea", "composite": True,
                                 "composites": {"client": {"broker": ["read-token"]}}}]}


def readable_tokens_on(realm):                # B2: each brokered user gets the role directly
    realm["identityProviders"][0]["addReadTokenRoleOnCreate"] = True


def read_token_for_another_client(realm):     # B2: another application's tokens carry it
    realm["clients"][1]["protocolMappers"].append({"name": "rt", "protocolMapper": "oidc-hardcoded-role-mapper",
                                                    "config": {"role": "broker.read-token"}})


def read_token_in_a_group(realm):             # B2: a group's members hold it
    realm["groups"] = [{"name": "everyone", "clientRoles": {"broker": ["read-token"]}}]


def read_token_not_on_the_client(realm):      # B2: Elitea's own tokens would be refused (403)
    realm["clients"][0]["protocolMappers"] = [m for m in realm["clients"][0]["protocolMappers"]
                                              if m["protocolMapper"] != "oidc-hardcoded-role-mapper"]


def common_issuer(realm):                     # N3: any tenant's people
    realm["identityProviders"][0]["config"]["issuer"] = "https://login.microsoftonline.com/common/v2.0"


def store_tokens_off(realm):
    realm["identityProviders"][0]["storeToken"] = False


def tid_importer_not_forced(realm):
    realm["identityProviderMappers"][0]["config"]["syncMode"] = "IMPORT"


def attribute_editable_by_users(realm):
    component = realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"]
    profile = json.loads(component["kc.user.profile.config"][0])
    next(a for a in profile["attributes"] if a["name"] == "entra_oid")["permissions"]["edit"].append("user")
    component["kc.user.profile.config"] = [json.dumps(profile)]


@pytest.mark.parametrize("mutate, guard", [
    (second_tid_mapper, "exactly one mapper puts claim 'tid'"),
    (hardcoded_oid_in_optional_scope, "exactly one mapper puts claim 'oid'"),
    (oid_in_realm_default_scope, "exactly one mapper puts claim 'oid'"),
    (referenced_scope_missing, "every client scope the client's tokens can get is in the file"),
    (script_mapper, "no script mapper"),
    (other_idp_writes_oid, "no other identity-provider mapper"),
    (same_idp_hardcodes_tid, "no other identity-provider mapper"),
    (ldap_writes_tid, "no user federation"),
    (read_token_in_default_role, "no role, group or user holds broker read-token"),
    (readable_tokens_on, "Stored tokens readable is off"),
    (read_token_for_another_client, "no other client or client scope adds broker read-token"),
    (read_token_in_a_group, "no role, group or user holds broker read-token"),
    (read_token_not_on_the_client, "Elitea's client tokens carry broker read-token"),
    (common_issuer, "issuer is the Entra v2 issuer of one tenant"),
    (store_tokens_off, "Store tokens is on"),
    (tid_importer_not_forced, "Entra tid -> a user attribute"),
    (attribute_editable_by_users, "user profile declares 'entra_oid'"),
], ids=lambda value: getattr(value, "__name__", ""))
def test_each_broken_realm_fails_its_check(check, realm, mutate, guard):
    broken = exported(realm)
    mutate(broken)
    names = failed(check, broken)
    assert names and all(guard in name for name in names), names


def test_another_tenant_than_the_expected_one_fails(check, realm):
    assert failed(check, exported(realm), tenant="99999999-0000-4000-8000-000000000001") == [
        "issuer is the Entra v2 issuer of one tenant (no common/organizations) and of the given tenant"]


def test_a_placeholder_issuer_passes_only_as_an_import_template(check, realm):
    assert failed(check, realm, template=False) == [
        "issuer is the Entra v2 issuer of one tenant (no common/organizations)"]

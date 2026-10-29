# Runbook: Microsoft (Graph/SharePoint) access for people who sign in through Keycloak

C-1009, EliteaAI/elitea_issues#6754, step 4b. Audience: the team that runs the organisation Keycloak and the Elitea
deployment. No secret appears here; every value in `<angle brackets>` is yours to fill in. Files next to this one:
`check_realm.py` (the realm check) and `realm-example.json` (the reference realm of the local overlay).

**What it does.** A person signs in to Elitea through the organisation Keycloak, which brokers the login to Entra.
Keycloak keeps the Entra token response (Store tokens). Right after the login, Elitea (`auth_oidc`) fetches that
response once from the realm's broker token endpoint and keeps the person's Entra access token for as long as their
Elitea session lives. When an agent uses a credential that acts with the person's Microsoft sign-in, Elitea exchanges
that token on behalf of the person (Entra on-behalf-of) — the same as for a direct Entra login. Logout drops it.

**What you trust.** Elitea takes the person's Entra identity (tenant id `tid`, object id `oid`) from the realm's tokens.
Listing the realm in Elitea (`entra_obo_broker_issuers`, §3) means trusting the realm to put only Entra's own values
there: keep the two identity attributes admin-only and force-synced, and keep realm-admin rights to the people who run
Keycloak. `check_realm.py` fails a realm in which anything else could set them.

## 1. Entra (app registrations)

1. On the Entra **web client** that Keycloak uses to broker (the one Elitea signs people in with), add the redirect
   URI (platform **Web**): `https://<keycloak host>/realms/<realm>/broker/<alias>/endpoint` (alias below: `entra`).
   Entra accepts plain `http` only for `localhost` (the local overlay uses
   `http://localhost:8082/realms/elitea/broker/entra/endpoint`); any other host needs `https`.
2. The platform **API app** must expose the delegated scope `access_as_user`, issue **v2** access tokens
   (`requestedAccessTokenVersion = 2`; Elitea refuses v1 tokens), and list the web client as a known client
   application. Its own delegated Graph/SharePoint permissions need admin consent (as for the direct Entra login).
3. Keycloak authenticates to Entra with a client secret of the web client. Store it in Keycloak's vault where you can.
   Elitea's pylon_auth holds the same secret to renew brokered sign-ins (§3), so the secret has **two holders**;
   rotate it on your usual schedule and in both places.

## 2. Keycloak (admin console, Keycloak 26)

1. **Identity providers → Add provider → OpenID Connect v1.0** (the generic one, not "Microsoft").
   - Alias `entra`; display name as people should see it on the login page.
   - Discovery endpoint `https://login.microsoftonline.com/<tenant id>/v2.0/.well-known/openid-configuration`
     (your tenant's id, never `common` or `organizations`; fills issuer, authorization, token, JWKS and logout URLs).
   - Client authentication: client secret sent as post; client id = the web client; client secret (vault reference).
   - **Store tokens: on. Stored tokens readable: off** (the read right comes from Elitea's client only, step 5).
   - Validate signatures: on, Use JWKS URL: on. PKCE: on, method S256.
   - Disable user info: on (the access token is for the platform API, not Graph, so the user-info call would fail).
   - Scopes: `openid profile email offline_access <Application ID URI of the platform API>/access_as_user` (the
     Application ID URI already starts with `api://`, e.g. `api://elitea-api/access_as_user`).
   - Sync mode: force.
   - **Trust email: off** for an organisation realm, unless Entra sends a verified e-mail you rely on. Elitea links a
     person to an existing user by e-mail when `identity_key: email` (§3); an e-mail Keycloak marks as verified only
     because the provider sent it is not proof the person owns it. The local overlay keeps it on (one known tenant,
     fixture users).
2. **Identity provider `entra` → Mappers → Add mapper**, type *Attribute Importer*, sync mode *Force*:
   claim `tid` → user attribute `entra_tid`; claim `oid` → user attribute `entra_oid`; claim `email` → `email`.
   No other mapper — of this or any other identity provider, or of a user federation (LDAP) — may write `entra_tid` or
   `entra_oid`.
3. **Realm settings → User profile → Create attribute** `entra_tid` and `entra_oid`: who can edit **admin only**, who can
   view admin only, not required. People must not be able to change these in the account console.
4. **Clients → `<Elitea's client>` → Client scopes → `<client>-dedicated` → Add mapper → By configuration → User
   Attribute**: user attribute `entra_tid` → token claim `tid`; user attribute `entra_oid` → token claim `oid`; claim JSON
   type String; *Add to ID token* on, *Add to access token* on, *Add to userinfo* on. These must be the **only** sources
   of the claims `tid`/`oid` in Elitea's tokens: no other mapper on the client, in its default or optional client
   scopes, or in the realm's default scopes may emit them (a person can ask for an optional scope themselves).
5. **Same dedicated scope → Add mapper → By configuration → Hardcoded role → role `broker` `read-token`.** This puts the
   right to read the stored Entra token into tokens issued **to Elitea's client only**. Do not give `read-token` to
   people (not in the default roles, not by "Stored tokens readable", not through a group or role): every other
   application's tokens would then carry it too and could read the person's Entra tokens. If your realm already grants
   it that way, remove it there.
6. **Clients → `<Elitea's client>` → Settings → Valid post logout redirect URIs**: Elitea's logout callback
   (`<Elitea base URL>/forward-auth/auth_oidc/logout_callback`). Without it Keycloak refuses Elitea's logout
   ("Invalid redirect uri") and the platform session is not ended. Note that a logout through Keycloak is forwarded to
   Entra as well (the broker's upstream logout): the person's Microsoft browser session ends with it, and the next
   sign-in asks for credentials again.

**Check the realm.** Export it (Realm settings → Action → Partial export, include groups and roles and clients) and run:

```bash
python3 check_realm.py <export.json> --alias entra --client <Elitea's client id> --tenant <Entra tenant id>
```

Every line must read `PASS` (23 checks: Store tokens on and readable tokens off, a single-tenant v2 issuer, signature,
PKCE, scopes, the three IdP mappers with force sync, no other writer of the two attributes (other providers, LDAP),
exactly one source per identity claim across the client's own, default, optional and realm-default scopes, no script
mapper, `read-token` from Elitea's client only and held by nobody, the admin-only profile attributes). The script reads
the file only and never prints a secret (the export masks the client secret anyway). For an import file whose ids are
`${...}` placeholders, add `--template` instead of `--tenant`.

## 3. Elitea configuration

**pylon_auth, `auth_oidc`** (the login is Keycloak's; the ids are public, the secrets come from environment variables):

| Key | Value |
|---|---|
| `issuer`, `metadata_endpoint` | `https://<keycloak host>/realms/<realm>` (as in the tokens) and its `/.well-known/openid-configuration` |
| `client_id`, `client_secret`, `scope` | Elitea's Keycloak client; `openid profile email` |
| `subject_claims` | `{tid: tid, oid: oid}` (the claims of step 2.4) |
| `obo_custody_enabled` | `true` |
| `obo_api_client_id` | the platform API app's client id |
| `obo_assertion_source` | `keycloak_broker` (default `login` = direct Entra login) |
| `obo_broker_alias` | `entra` |
| `obo_broker_refresh_client_id` | the Entra web client id (renews the Entra token at Entra, never at Keycloak) |
| `obo_broker_refresh_client_secret_env` | the name of the environment variable holding the web client's secret |
| `obo_broker_refresh_scope` | the scopes of step 2.1 |
| `obo_custody_key_env` | default `ELITEA_OBO_CUSTODY_KEY` (32+ characters, the same value in pylon_main) |

The broker endpoint is called on the host of the realm's token endpoint (from discovery), for the issuer's realm, so
pylon_auth may reach Keycloak by an internal name while the issuer is the browser-facing one. Without the three
`obo_broker_refresh_*` keys a sign-in serves runs until its Entra token expires (about an hour) and a sign-in whose
stored Entra token has already expired (a Keycloak single-sign-on login reuses the stored one) keeps nothing; the person
then signs in again. `obo_broker_insecure_dev_http` is for the local overlay only (http on `localhost` names).

**pylon_main, `auth` identity verifier** (`identity_verifier.session_user`): `tenant_id` = the Entra tenant id;
`audience` = Elitea's Keycloak client id; `issuer` (as in the tokens) and `jwks_uri` of the realm;
`subject_claims: {tid: tid, oid: oid}`; `require_nbf: false`; `delegation_token: id_token`.

**pylon_main, `elitea_core`**: `entra_obo_client_id` (platform API app), `entra_obo_client_secret_env`,
`entra_obo_custody_key_env`, and `entra_obo_broker_issuers: ["https://<keycloak host>/realms/<realm>"]` (exact string;
without it a brokered login is refused `DENIED_ASSERTION_SOURCE_UNSUPPORTED`; listing it means trusting the realm's
identity attributes, see the top). Credentials that act with the person's sign-in keep `assertion_source: login` in
their descriptor: "login" is the person's own sign-in, direct or brokered.

**Where the secrets go** (one service each, never an env file every pylon loads): Keycloak — the web client secret;
pylon_auth — the custody key and the web client secret (renewal); pylon_main — the platform API secret and the custody
key; pylon_indexer — none.

**Moving existing users (identity migration).** With `subject_claims: {tid: tid, oid: oid}` the identity of a realm
user is `(issuer = the realm, Entra tid, Entra oid)`.
- Elitea records a subject only on a user that has none (`identity_key: email`, first login). A user already linked to
  another subject — a direct Entra login (issuer = Entra) or an earlier realm subject (`sub`) — keeps it, the login logs
  a WARNING "carries a different IdP subject", and governed runs are refused `IDENTITY_SUBJECT_UNLINKED`. For each such
  user an operator clears the three `idp_*` fields (the next login records the brokered subject) or sets them to the
  realm issuer and the person's Entra tenant and object id.
- Realm users without an Entra link (local Keycloak users) get no governed identity at all: every governed run under
  Enforce is refused `IDENTITY_TENANT_MISMATCH`, not only runs with delegated credentials.
- Grants are per subject `idp:<tenant id>:<object id>`: grants made for the same people under a direct Entra login still
  apply; grants made under an earlier realm subject (`sub`, realm tenant) do not and must be made again.
- After the migration, prefer `identity_key: idp_subject` (users found by their subject, not by e-mail).

## 4. After rollout, verify

1. A person signs in through Keycloak with Microsoft. pylon_auth logs no `OBO custody was not kept` line for that login.
2. That person runs an agent whose SharePoint credential acts with their Microsoft sign-in, under Enforce: the run
   gets data (or an empty list for an empty site), and the audit shows `CREDENTIAL_RELEASED_DELEGATED`.
3. The person signs out and runs it again: the run is refused `DENIED_ASSERTION_UNAVAILABLE` with the text asking them
   to sign in again.

## 5. Failure signatures

| Where | Signature | Meaning | Fix |
|---|---|---|---|
| pylon_auth start | ERROR `OBO custody is enabled but … is missing` | a key, the API client id, a known source, or a usable broker endpoint (the realm's https token endpoint, a valid alias) is missing | complete §3 |
| pylon_auth start | WARNING `… has no refresh client` | `obo_broker_refresh_*` incomplete | add them, or accept hourly sign-ins |
| pylon_auth login | WARNING `… realm's token carries no Entra identity …` | a realm user who did not sign in through the Microsoft broker | sign in with Microsoft on the Keycloak page |
| pylon_auth login | WARNING `… answered 403 (…read-token…); an earlier sign-in of the person is dropped` | Elitea's client tokens lack `broker` `read-token` | §2.5 |
| pylon_auth login | WARNING `… answered 400 …; … dropped` | not linked to the broker, Store tokens off, or the session token was refused | §2.1 |
| pylon_auth login | WARNING `… answered 404 …; … dropped` | Keycloak stored no token for this person yet (Store tokens switched on after their last brokered login) | sign in again |
| pylon_auth login | WARNING `… not a v2 token of this person for the platform API` | the API scope is missing from §2.1, the API app issues v1 tokens, or the realm maps other `tid`/`oid` than Entra's | §1.2, §2.1–2.4 |
| pylon_auth login | WARNING `… has expired and no refresh client is configured` / `… could not be renewed` | a single-sign-on login reused an expired stored token | §3 refresh keys; or sign in again through Microsoft |
| pylon_auth login | INFO `… had expired and was renewed` | as above, renewed at Entra | — |
| pylon_auth login | WARNING `… failed (<exception type>)` / `… no token response …` | Keycloak unreachable, too slow or not answering JSON | network, Keycloak health |
| run (admission) | `IDENTITY_TENANT_MISMATCH` / `IDENTITY_SUBJECT_UNLINKED` | the Keycloak token has no Entra `tid`/`oid` (a local Keycloak user, or the mappers of §2.2–2.4 are missing), or the user is linked to another subject (§3 migration) | §2; §3 migration |
| run (release) | `DENIED_ASSERTION_UNAVAILABLE` | no Microsoft sign-in kept for the person (signed out, session expired, one of the login warnings above) | sign in again |
| run (release) | `DENIED_ASSERTION_SOURCE_UNSUPPORTED` | the realm is not in `entra_obo_broker_issuers` | §3 elitea_core |
| run (release) | `DENIED_SUBJECT_MISMATCH` | the credential is for another tenant or another person | use the person's own credential |
| run (release) | `DELEGATION_EXCHANGE_FAILED` | Entra refused the exchange (consent or site grant missing) | §1.2, site grant |
| Keycloak events | `IDENTITY_PROVIDER_LOGIN_ERROR` "Wrong issuer from token" / `invalid_scope` | issuer or scopes of §2.1 do not match the tenant | §2.1 |

## 6. What to know

- Keycloak's database holds the stored Entra token responses by design (Store tokens). Elitea keeps the person's
  token only in its session store, for the session's lifetime, and never writes Graph tokens anywhere.
- Taking the right away in Keycloak (removing the hardcoded role mapper, Store tokens off) takes effect at the
  person's **next** Elitea login, which then also drops the sign-in Elitea kept from an earlier login. Until then an
  existing Elitea session keeps working, and Elitea renews its Entra token at Entra (not at Keycloak). To cut a person
  off at once, sign them out of Elitea (or disable them).
- The broker call is one HTTPS request per login: an 8 s budget checked between reads (each read waits at most 4 s),
  at most 64 KiB, no redirects, only the realm's token-endpoint host. Runs add no call beyond the direct Entra case.

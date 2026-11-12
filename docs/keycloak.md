# Keycloak (auth)

Reference and explanation for the operator and for an engineer changing the Keycloak service. The
code is the truth: `compose.yaml` (service, labels, pins, secrets), `keycloak/master.yaml` and
`keycloak/realm.yaml` (the realms), `keycloak/go-live` (`--help` lists its steps) and
`probe/keycloak/` (what the service must keep doing). The platform picture is
[architecture.md](architecture.md).

## In plain words

Keycloak is the one login for all the apps behind this edge: a person signs in
once and every app asks Keycloak who they are, so no app keeps its own
passwords.

It has two doors. The **public door** is the login page at
`auth.<EDGE_DOMAIN>`; it comes through the platform's Cloudflare tunnel, where
the platform's Keycloak answers it, and shows only what a login needs (see
[Doors](#doors-issuers-and-configuration)). The **admin door** `http://localhost:8090` belongs to hal's own Keycloak, the stopped rollback
unit, not to the live login: it reaches that unit's admin console and master realm, works on this
PC only, is never routed through the tunnel, and answers only while the unit runs. Administering the
live login is the platform's, not this door's.

The secrets (the database password, the password of the tool that applies the
configuration, and a temporary admin password) are three files in
`~/.secrets/keycloak/`; each confidential app client has one more file of its own in
`~/.secrets/keycloak/clients/`. No file of this repository holds one.

"Realm as code" means the settings of the logins (groups, clients, login rules)
are YAML files in `keycloak/`, applied by a tool, not clicked together in the
console. Only the people and their group memberships are managed in the
console. Change the YAML and apply it again, and the running Keycloak follows.

Going live needs you in one place only: in the browser, to create your own
admin with a second factor (a machine must not hold that). Everything else is
`keycloak/go-live` (see [Go-live](#go-live)). The sections below are the reference.

## Doors, issuers and configuration

The one login for the apps: Keycloak with its own Postgres (`keycloak-db`,
volume `keycloak-db`), both on the `keycloak` network (`172.31.253.0/24`, which
`KC_PROXY_TRUSTED_ADDRESSES` names). While the unit runs, Traefik reaches
Keycloak on port 8080 in two ways; the routing rules are the labels of the `keycloak` service in `compose.yaml`:

| Entrypoint | Host | Admits |
|---|---|---|
| `edge` (`127.0.0.1:8081`, hal's tunnel target) | `auth.<EDGE_DOMAIN>`, which the platform's tunnel serves; this route answers it again after a rollback | the `hallucinai` realm, its resources and the versioned static resources only; everything else, `/resources/master/…` included, is Traefik's 404, except the bare `/`, which redirects (302) to the realm's account page |
| `admin` (`127.0.0.1:8090`, this PC only) | `localhost` | the admin console and the master realm (`http://localhost:8090/admin/`); `127.0.0.1:8090` answers a bare 404 by design, because the WebAuthn rpId is a hostname |

The catalog host `auth` carries `tunnel: platform`: its record points at the platform's tunnel,
which serves `auth.<EDGE_DOMAIN>`, and the platform's Keycloak answers it. This unit is switched
off (`hal stop keycloak`) and stays in the catalog as the rollback target until hal stops. `hal apply`
leaves it stopped, holds the realm step and the LiteLLM admin rows; the platform owns the record of `auth` and the tunnel ingress;
it does not ask `auth`'s `ready` path, because a host on another tunnel is not asked. Rolling back
is `hal start keycloak`, the platform's change that points `auth` at hal's tunnel, then reverting the key, then `hal update` and `hal apply`. hal's speech
service and the MCP servers behind traefik-mcp read the key set from this Keycloak at
`keycloak.mcp.internal`, so while it is stopped they stop accepting tokens when their key cache runs
out.

The public issuer is `https://auth.<EDGE_DOMAIN>/realms/hallucinai`; the
master realm's issuer is `http://localhost:8090/realms/master`. Every master
login needs a password and a second factor: an administrator without one must
enrol TOTP before the console opens, and may add a passkey (rpId `localhost`)
afterwards. A password grant on the master realm (`admin-cli`, `kcadm.sh`)
demands a TOTP code as well, so an administrator without TOTP gets no token
that way. Remote administration while travelling arrives with the A9 travel
setup (an SSH or Tailscale forward to 8090), never through the tunnel.

Configuration is code: `keycloak/master.yaml` and `keycloak/realm.yaml`, applied
by keycloak-config-cli. People and their group memberships are managed only in
the admin console; no file lists a person. An invited person gets the username
they ask for, a pseudonym included, and nothing checks the names they enter at
first sign-in, because the privacy notice promises pseudonymous use (§ 19 Abs. 2
TDDDG; the operator's ruling of 22.10.2026, edge#312). The songmaker, hopin,
presentator and skat clients are in `realm.yaml`, each secret the file
`~/.secrets/keycloak/clients/<clientId>` (`keycloak/go-live` makes it;
presentator's one client serves `presentator` and `presentator-talk`); the other
app clients arrive at K13/K14.

songmaker signs people in only: it has no service account and allows no device grant, and its
client names the device grant as off, so the import's merge cannot keep an earlier on. hopin's
default scopes are exactly `basic`, `profile`, `groups`, `roles` and `service_account`: it reads no
email, web origin or acr.

hopin and presentator are the callers of the speech service (#674, #941). Their service accounts are
the only users `realm.yaml` lists, each holding the realm role `speech-workload` and no group.
Whoever holds such an app's client secret can therefore get a workload token for that app, which is
the design; the secret stays the app's own file. `speech-service-audience` is an optional scope of
these two clients alone, so a token carries the `speech-service` audience only when its request names the
scope: `scope=speech-service-audience` on the `client_credentials` grant, or `openid speech-service-audience`
on the authorization request. The scope is an `oidc-audience-mapper` on the access token only.
songmaker cannot ask for it: the request is refused with
`invalid_scope`. The speech service is a bearer-only client `speech-service`, and
the group `/services/speech-service` has no subgroup: the service admits exactly that path. A person
reaches the service by being a member of the group and signing in to hopin or presentator with the scope.

The group `/services/litellm/admin` has one reader, `hal apply`'s key step (docs/agent-service.md,
„The API route“): at each plan the realm observer's members mode reads the ids of its direct members
and the realm's issuer from its discovery document, the one GET the observer sends without a token,
and the step links those members' LiteLLM customer rows to the admin budget. The group starts empty;
who joins it is decided in the admin console.

What an audience scope does under other settings was measured on Keycloak 26.8.1 (cells U3, U4 and RF1
to RF2 of the Keycloak probe, #674). They run on clients, a scope and a realm role the probe makes: the
scope is a copy of `speech-service-audience` read from `realm.yaml` (so `include.in.token.scope` is
`"false"`), and the clients have hopin's default scopes without its audience scopes. A workload token
that asks for the scope has the audience `probe-measured-service` and also `account` (the default roles'
`account` client roles), the role, and the default roles with `offline_access` and `uma_authorization`. Without the
default roles on the service account, the `aud` is exactly the service and the role is kept. With
`fullScopeAllowed` off, the `aud` is exact but the token has no realm role at all; adding the role as a
realm scope mapping on the client keeps it. A session signed in while the scope was a default keeps
the audience on a refresh after the scope became optional, with or without naming it, and so does a
session that named the scope at sign-in; the access token's `scope` is `openid profile groups` either
way. A session signed in with `openid` after the move gets no audience from a refresh that names the
scope: the answer is a 200 whose `aud` is `account` alone. A new authorization request that names the
scope, in that session's browser, is answered with a redirect carrying a code, with no login page.
The answers belong to this Keycloak version: the probe holds only that each ran, so an image upgrade
(#610) can change one without failing it.

The cell N1 is not version-bound: webauth's group check (`current_groups`) refuses a refreshed ID token with a `nonce` key, so each app client's refreshed ID tokens must have none, and a Keycloak upgrade that adds the key fails the probe.

Every login app follows the same shape. It gets its own client in `realm.yaml`, with its secret in its own file under `~/.secrets/keycloak/clients/`. Its `backchannel.logout.url` is `http://<app>.hallucinai.de:<port>/auth/backchannel-logout`, with `backchannel.logout.session.required: "false"`; the host is an alias the app's web service gives itself. The call travels over the app's own internal network `hal_backchannel_<app>`, which only `keycloak` joins on edge's side and the app joins as an external network, so no app sees another's. The public host lists the path in `deny_public` (`fleet.yaml`). An app that holds a refresh token per session names `use.refresh.tokens: "true"` (hopin); one without the line keeps Keycloak's default. Skat, songmaker and HopIn are the exception: they run on the platform, which this Keycloak's call does not reach, so after a rollback a sign-out ends their sessions only at their lifetime. Skat's client has no `backchannel.logout.url`; songmaker's and HopIn's clients keep theirs, with the networks below, and no app joins those networks.

songmaker's client declares the back-channel logout call
`http://songmaker.hallucinai.de:8080/auth/backchannel-logout` (the name is an alias a songmaker web
service gives itself) over the internal network `hal_backchannel_songmaker`, which only `keycloak` joins
on edge's side. songmaker ignores the session id and ends every session of the person, so the
client does not require one. The public tunnel denies the path, matched on the recursively decoded
path and on the host with any port. songmaker runs on the platform, where this Keycloak's call does not reach it,
so after a rollback a sign-out ends a songmaker session only at its own limit. The platform's Keycloak owns its back-channel logout today.

Which console actions send that back-channel logout was measured on Keycloak 26.8.1 (cell LA1 of
the Keycloak probe). For each action a fresh user signed in to a client with HopIn's ruled
settings, which match songmaker's logout lines (#254): `backchannel.logout.url` on the internal
network and `backchannel.logout.session.required: "false"`, plus `use.refresh.tokens: "true"`. The admin call succeeded, and a test relying
party counted a logout token only when its `sub` was that user's and it arrived within 20 seconds.
A sign-out of the user's sessions, run first as the control, arrived. For disabling the user,
deleting the user and removing the user from a group, no matching logout was observed within
20 seconds. This describes what Keycloak did in that configuration, not any app's erasure: whether
an app ends or erases an account on a sign-out is the app's own (hopin#79 S4).

HopIn's client declares the same call over its own internal network `hal_backchannel_hopin`, which
only `keycloak` joins on edge's side: `backchannel.logout.url`
`http://hopin.hallucinai.de:8080/auth/backchannel-logout` and `session.required: "false"`. HopIn
runs on the platform, where this Keycloak's call does not reach it, so after a rollback a sign-out ends a HopIn session only at
its own limit. The platform's Keycloak owns its back-channel logout today. HopIn
holds a refresh token per session in memory (operator ruling of 27.10.2026, #506, which reverses
hopin#79 finding 28), so its client names `use.refresh.tokens: "true"` instead of leaving the line
out: a line deleted from the file may survive in a live client that the import merges.

presentator's client declares the same call over its own internal network `hal_backchannel_presentator`
(only `keycloak` joins it on edge's side), on presentator's own port: its client has
`backchannel.logout.url` `http://presentator.hallucinai.de:8000/auth/backchannel-logout` and
`session.required: "false"`, and keeps Keycloak's default refresh token. The platform's Keycloak
cannot reach that network, so a central sign-out ends presentator's session on hal only at its own
limit; the call travels only while this Keycloak runs.

### Theme and language

Keycloak's login and account pages use the realm theme `hallucinai`
(`loginTheme` and `accountTheme` in `realm.yaml`). Its files sit in
`keycloak/themes/hallucinai/{login,account}`; compose mounts the directory
read-only into the `keycloak` service, so a change of look changes theme files
only, never the realm. The email and admin themes, the master realm and the
admin console stay Keycloak's own.

The themes give both pages the look of hallucinai.de, light and dark by the
device, with the violet main button of songmaker's vocabulary
(`docs/design/keycloak-theme.html` is the picture): the wordmark, hallucinai's
colours and shapes over Keycloak's PatternFly, the favicon, and Impressum,
Datenschutz and Nutzungsbedingungen as the kit's legal row on the sign-in
pages. The tokens and the fonts (Oswald and Open Sans,
with their licences, so no page asks a third party) come from the installed
appkit: the appkit step of `hal apply` writes `appkit-<version>/` (git-ignored)
into each theme's `resources/`, and `styles=` lists its `appkit.css` first, then
the theme's own file with the app colour and the shapes (`css/edge-3.css` for
login, `css/edge-2.css` for account). The theme
files reach Keycloak on `hal update` of the live checkout, the appkit
directory on `hal apply`, so a restart between the two serves pages without
tokens. They are CSS, `footer.ftl` and message texts on top of `keycloak.v2` and
`keycloak.v3`, never a copy of Keycloak's `template.ftl`. A Keycloak update
re-checks `content.json` (a copy of keycloak.v3's navigation list) and the
PatternFly selectors at both widths. The account console hides its "Gruppen"
page (its own `content.json`) and the sentences under titles and sign-in
methods; its "Anwendungen" lists only apps a person has used, because the app
clients carry `alwaysDisplayInConsole: false` in `realm.yaml`. What Keycloak
does not let a theme change stays Keycloak's: the fields and paths the realm
offers (no registration, no "Passwort vergessen?", no mail: the operator resets
passwords in the admin console), the account console's layout and its pages, the
browser's passkey window and the code page's content.

Two places deviate from the legal-row rule of overnightworks/appkit#82, which owns the rule. The account console (keycloak.v3, React) shows no legal links, because the account theme only restyles Keycloak's React console with CSS and resources, which leaves no place for the kit's `AccountMenu`. The sign-in pages show the legal row inside the card, in the card-footer slot that `footer.ftl` fills, not under it: the inherited keycloak.v2 login template gives a theme no slot outside the card, and putting the row under the card would mean keeping an own copy of `template.ftl` in step with every Keycloak update.

The pages appear in German and English: the browser's language decides,
English applies when neither is asked for, and the pages carry a language
switcher (`internationalizationEnabled`, `supportedLocales`, `defaultLocale`
in `realm.yaml`).

Keycloak in `start` mode caches themes, so a changed theme file shows after
`docker compose --profile keycloak restart keycloak`; that is not a realm
change. Keycloak's gzip copies of theme files (`data/tmp/kc-gzip-cache`) are
never compared with the file, so that folder is a tmpfs in `compose.yaml` and a
restart starts it empty; without it a file that a parent theme served before
would stay stale behind Cloudflare, which always asks with gzip.
`/resources/<version>/...` is served with `Cache-Control: max-age=2592000`
(30 days), and the five-character version survives a plain restart, so a
restart keeps the same URL. Cloudflare caches css, js, svg, ico and woff2 for 30
days under that URL as well, and a browser keeps them as long. A file changed in
place therefore keeps coming from those caches; a look change names a new file
(for a stylesheet, `styles=` in `theme.properties`; appkit's path changes with each
release, and a restyled `css/edge-3.css` takes a new name). A purge at Cloudflare
clears only Cloudflare's copy; a browser that already holds the old file keeps it.


> **The apply adds and changes, and deletes no undeclared top-level object and no person.**
> `compose.yaml` sets every `IMPORT_MANAGED_*` type of keycloak-config-cli 6.5.1 to `no-delete`,
> the cache off, and `IMPORT_USERS_MERGEROLES`/`MERGEGROUPS` on. What the console creates on its
> own stays: people, their memberships, and the groups, clients, roles and top-level flows the file
> does not declare. A console addition inside an object the file declares is part of that object
> and is reset to the file with it, as listed below. No person is ever deleted (a service-account
> user that a console-enabled service account on a declared client created goes with that reset,
> below):
> - **Stays:** an object the file stopped listing. Renaming a group in the YAML therefore creates
>   the new group and leaves the old one.
> - **Reset:** a console change to an object the file declares is reset to the file on the next
>   apply, together with what hangs off that object. The probe (proofs 3c and 3d) measures these, except where marked not measured:
>   - a step or subflow in a declared flow (`browser-mfa-forms`, `direct-grant-mfa-totp`);
>   - a mapper on a declared client scope (the scope `groups`); a mapper on a declared client is
>     ruled the same way but not measured;
>   - a default scope on a declared client that lists its scopes (songmaker, hopin, presentator;
>     an optional scope is ruled the same way but not measured), while a client without scope lists (`speech-service`) keeps its additions;
>   - a client role on a listed service account (`service-account-presentator`); its realm roles
>     and groups stay;
>   - a service account turned off in the console on a declared client (hopin), which the apply
>     turns on again, which recreates its user with its roles and no group;
>   - a flow binding override on a declared client.
>
>   A change to a declared object is made in the file, by an agent, never in the console. Deleting
>   a group, client or role is done in the admin console, after a backup, with your yes. The realm
>   observer (`realm-observer`, `src/hal/stack/realm/observe.py`) reads the realms before and after,
>   and `hal.stack.realm` compares the two reads and prints one line per change with its realm.

### Terms of use

Every account is asked once, at its first sign-in, to accept the terms of use: `realm.yaml` declares the
required action `TERMS_AND_CONDITIONS` as enabled and default, so a new account carries it. The page shows
a short sentence with a link to the central terms page (`https://hallucinai.de/nutzungsbedingungen`, which the platform serves)
and Keycloak's own Accept and Decline buttons, in German or English by the browser; the words are `termsTitle`
and `termsText` in the theme's message files. The text itself exists only on the central page. The
acceptance counts for the whole Keycloak account, so every app at once. Decline signs nobody in and
removes the stored time; the account stays and is asked again at the next sign-in. A service account
(`client_credentials`) is never asked.

Keycloak stores the time of the last acceptance as the user attribute `terms_and_conditions`, in Unix
seconds, and no list of earlier ones. Only an admin sees it in the console; the person's account page
and the tokens do not carry it, and an admin cannot set it, only ask again. A deleted account takes its
time with it, except in the backups.

Ask one person again: open the account in the admin console, add "Terms and Conditions" under Required
user actions and save. This is also how an existing account is asked once after the action went live,
because Keycloak gives the action by itself only to new accounts. Ask again when the terms change in
substance; a typo or a new link is no reason.

The action reaches Keycloak in this order: update the checkout (`hal update`), restart Keycloak
(Theme and language), then `hal apply`, which applies the realm; the public legal pages that the action
links to are the platform's. The
messages must be served before the action is on, or the page shows Keycloak's placeholder text.

Switch it off with `enabled: false` and `defaultAction: false` in the block, never by deleting the block:
the apply deletes nothing, so a removed block leaves the action on.

### The agents client

`agents` is the one public client for a person's own AI agents. It signs in with the authorization code and PKCE
(S256) at the single loopback address `http://localhost:28471/callback`, has no secret and no refresh token, and
asks for consent at the first sign-in. Its default scopes are `basic` and `groups`; `mcp-songmaker`,
`mcp-presentator`, `mcp-hopin` and `offline_access` are optional. Each `mcp-<app>` scope puts exactly one
audience, `https://<app>.hallucinai.de/mcp`, into the access token and names the app on the consent page. The
token has the type header `at+jwt`, `azp` `agents`, the person's group paths and no role claim, and lives the
realm's 300 seconds (the operator's ruling of 01.11.2026): an agent signs in again when it expires.

The realm grants no right with it: any account can get such a token, and an app admits it only for a member of
its group `/apps/<app>/mcp`, which webauth checks. The three groups are empty; who joins one is decided in the
console, after the app's privacy notice names the agent.

The Keycloak probe (cells A1 to E1) measured on the pinned version:

- The consent page lists `offline_access` beside the app, and the scope of another app meets it again.
- Discovery through the edge answers only in the appended form
  `/realms/hallucinai/.well-known/openid-configuration`; the two inserted forms are 404.
- Client registration is refused for anonymous callers.

## Secrets

No secret is in any file of this repository or in any container's `Config.Env`. Compose mounts
the files from `${HOME}/.secrets/keycloak/` (the database password, the password of the tool that
applies the configuration, and the temporary admin's password); Postgres reads its password through
`POSTGRES_PASSWORD_FILE`, and `keycloak/entrypoint.sh` exports the others from `/run/secrets` into
the process and `exec`s Keycloak or keycloak-config-cli. Each confidential app client has one more
file, `~/.secrets/keycloak/clients/<clientId>`; `compose.yaml` names them as top-level secrets.
The files are 0644 inside their 0700 directories, because the container users must read them.
`keycloak/go-live` creates the three base files only when none exists; when only some exist it
refuses and names the missing ones, except that a `bootstrap-admin-password` that step 7 retired
counts as done. Each missing client file is created, so a later app that adds one secret to
`compose.yaml` gets only its file at the next go-live. It never overwrites a file.

`keycloak/secret-check/secret_check.py` keeps secrets out of the repository's YAML (the file's
header and `tests/test_secret_check.py` hold its rules); CI runs it. After changing the script's
dependencies run `uv lock --script keycloak/secret-check/secret_check.py` (not `uv lock`). The
quality gate (`quality / check`) additionally scans the whole history for literal-looking
secrets.

## Start and apply

Start the stack as in [stack.md](stack.md) (Start, readiness, stop; Keycloak comes with `hal
apply`), and wait until Keycloak answers the master realm on 8090. A realm change reaches it
through `hal apply`: merge the change to `keycloak/realm.yaml` or `keycloak/master.yaml`, update the
live checkout, run `hal apply`.

`hal apply` runs the realm step after the unit switches, when Keycloak is on, set up and running
and an input changed: `keycloak/realm.yaml`, `keycloak/master.yaml`, `keycloak/entrypoint.sh` or
config-cli's resolved definition (its whole service: the image pin, the `IMPORT_*` switches, its
binds and attachments) differ from what `applied.json` recorded after the last step, or Keycloak's
own import-checksum attributes differ from the recorded ones (a restored database, a go-live
import). Unchanged inputs mean the step does nothing: no backup and no run. The definition is
hal's digest of the resolved service with every bind inside the checkout relative to it, so moving
the checkout is no realm change. A rotated client secret alone does not trigger it, because the
definition covers a secret's attachment, not the content of its file; change a realm file or wait
for the next realm change.

The plan names the step in one line. After your yes it takes a Keycloak-only backup tagged
`pre-apply` (the last ten are kept, and those older than 90 days are dropped at the next forget of the app) and restore-tests that snapshot, observes both realms, runs
config-cli, observes again and prints one line per change. A Keycloak that should run and cannot be read is skipped: the step prints a `!` row,
`keycloak  realm skipped` with the reason, and the run ends partial (`error: partial, keycloak realm
skipped`, `next: hal apply`) and hal exits 3; when that is the only change, hal asks no yes and ends
`error: realm: Keycloak could not be read; not checked (…)`, `next: hal apply`, exit 3.
`hal backup` runs in a process group of its own, so Ctrl-C does not reach it. A step
that outlives its time or is interrupted sends it SIGTERM, as a systemd stop does, and waits two
minutes for its cleanup, which a further Ctrl-C does not shorten, and a `› keycloak  waiting  up to
2m00s for hal to clean up` row says so; only after that wait it kills the group.

A step that fails ends the run partial, hal exits 3, and it prints one red row, `✗ keycloak  realm failed
<cause> · <nothing applied | may be partly applied | applied, not observed>`. Under it, dim, stands
`pre-apply snapshot 37c2a560 · proven` (or `unproven`, when its restore test did not pass) once a
snapshot exists, and from the start of config-cli on `way back: docs/backup.md "Restore Keycloak" ·
the next apply repeats the step`; the way back is [Restore Keycloak](backup.md#restore-keycloak).
A failure before any snapshot prints the row alone. Then come `error: partial, keycloak realm
failed` and `next: hal apply`. A console change to a declared object that the apply resets is printed as "reset to the file" with the
snapshot ID, exit 0. Keycloak that is switched off or disabled is never started by the step: the
plan says its realm files wait. Keycloak that starts in the same run is checked by the next `hal
apply`.

The apply signs in as the `config-cli` service client and fails loudly on a `$(env:…)` variable
that is not set (`IMPORT_VARSUBSTITUTION_UNDEFINEDISERROR`). Whatever exists only in Keycloak
stays; deleting a group, client or role the YAML no longer lists is done in the admin console, with
your yes, after a backup. After the yes the step prints one row, `✓ keycloak  realm applied  1 change · snapshot 37c2a560
proven · 11s` (the first eight characters of the pre-apply snapshot, which `hal restore --snapshot`
takes), and under it one dim line per change, then one per group, client, client scope, realm role,
top-level flow and identity provider that the files do not declare (`only in Keycloak: hallucinai
group /console-made`), and last `only in Keycloak: nothing · 12 kinds not read` (or the count found, and
`1 realm not observed` between the two when a declared realm could not be observed). The kinds it cannot
read are `organizations`, `workflows`, `subComponents`, `scopeMappings`, `clientScopeMappings`,
`defaultGroups`, `clientPolicies`, `clientProfiles`, `authorizationSettings`,
`userFederationProviders`, `messageBundles` and `userProfile`; they are not listed, so the list
never claims more than it saw. Keycloak's
own objects are left out: flows by their `builtIn` flag, the rest by a list pinned to Keycloak
26.8.1 in `src/hal/stack/realm/reconcile.py`, which the probe's proof 3a keeps true in both
directions: a fresh import holds nothing only in Keycloak, and holds every pinned entry. The list appears
only when the step runs and never changes its outcome. A console change to a declared object is
reset by the next apply that runs the step, not by every apply.

## Go-live

`keycloak/go-live`, run from the checkout, as the operator, takes Keycloak live once: secrets,
first start and apply, your own admin with a second factor, and the retirement of the temporary
admin. An agent never runs it against the live project and never holds an admin credential.
`keycloak/go-live --help` lists its steps, each skipped when already done, so it can be run again
after any interruption; a failure ends with one line naming the step and exit code 1, and it never
prints a secret. Your own part is in the browser (step 7): a machine must not hold your second
factor. `fleet.yaml` names `keycloak/go-live` as Keycloak's setup, so `hal apply` asks and runs it in
your terminal on yes while it is not done.

While `~/.local/state/edge/stopped/keycloak` exists (`hal stop keycloak`), go-live refuses and
starts nothing; `hal start keycloak` ends the switch. `keycloak/go-live --check` asks nothing,
changes nothing and ignores the marker: its exit codes are in `--help`. It reads go-live's durable
trace, not Keycloak, and it is also the setup check of `hal apply --local` for the unit
`keycloak`.

## Patch upgrade

1. **Bump the pin** of `quay.io/keycloak/keycloak` in `compose.yaml` (version and digest), and of
   keycloak-config-cli if a build for the new version exists.
2. **Re-run the probe.** It runs beside the live edge, which stays up, and its cell N1 fails on a
   refreshed ID token with a `nonce` key: [probe/keycloak/README.md](../probe/keycloak/README.md).
3. **Apply** once the pull request is merged. `hal apply` names
   `keycloak recreate image … → … · snapshot first`. After its `yes` it takes and proves Keycloak's
   pre-apply snapshot (the dump holds signing keys and credential hashes; the backup keeps it
   encrypted, see [backup.md](backup.md)), then recreates Keycloak; Keycloak migrates its database
   on the first start of the new version. If the snapshot fails, the old container keeps running.
   If the new one does not run, the error line names the snapshot for `hal restore keycloak --live`
   ([backup.md](backup.md), „Restore Keycloak“).

## Probe

`probe/keycloak/probe.py` proves the service on a throwaway compose project (`edge-kc-probe`)
built from this checkout; [probe/keycloak/README.md](../probe/keycloak/README.md) holds the
command, the modes, the proofs, the exit codes, how to stop it and how to remove a stack it left.

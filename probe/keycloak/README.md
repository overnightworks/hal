# Keycloak probe

`probe.py` starts a throwaway Keycloak stack (own compose project, generated secrets in a scratch
directory, no live data) from this checkout. It runs beside the live edge, which stays up: its
Traefik entrypoints listen on two free loopback ports it picks (a copy of `traefik.yml` in the
scratch directory), its admin front end is `http://localhost:<admin port>`, and its keycloak
network takes a free /24 from 172.31.200.0 up. Both modes need an empty or new `--scratch`
directory and always tear the stack down. While a probe runs, `hal check exposure` reports its Keycloak as a
routing name that is not valid, by design of the `edge.name: PROBE` label that keeps the live Traefik away.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 720 \
        python3 probe/keycloak/probe.py [run|hold] --scratch DIR

Measured teardown: 11 s (K 50 s, CAP 720 s).

Before each `compose up` the probe writes appkit's tokens and fonts into this checkout, where the
themes read them (`appkit-<version>/` beside each theme's `css/`), through
`uv run --project <checkout> python -m hal.stack.appkit_step <checkout>`. Any interpreter starts the probe, but
`uv` must be on `PATH`; a failing write ends the probe before the stack exists.

An exported `DOCKER_GID` overrides the host's `docker` group id in the compose environment; unset
it if it is stale. The probe reaches Keycloak's admin entrypoint on the `admin_url` and the edge
entrypoint on the `edge_url` of the `READY` line; it has no flag for another address.

The `timeout` caps the whole command, bring-up included. When the cap is reached after `READY`,
its SIGTERM ends `hold` as a normal `HOLD ENDED` with exit 0 once the teardown succeeded, while
`timeout` itself exits 124, so `HOLD ENDED` alone does not mean you asked for the stop: your
proof window is bounded by that cap. A cap reached before `READY`, or a teardown that leaves the
stack behind, ends with `PROBE FAILED` and exit 1.

- `run` (the default) prints one `PROOF <n> held:` line per proof and ends with
  `PROBE PASSED: proofs 1-12 hold`. Besides the proofs below it holds: the public issuer and the path
  allow-list (1, 2a); the master issuer and the forced second factor on the admin entrypoint, for
  the console and for a password grant (2b); a failing undefined variable, a fresh apply, an
  unchanged export after a second apply that resets only the pinned console changes to declared
  objects and keeps every other console change, and a changed YAML that applies and deletes no
  undeclared top-level object and no person, with a seeded member untouched (3a-3d); the `groups`
  claim and the `agent-service` audience (4); a disabled user refused on refresh (5); a
  back-channel logout reaching the test relying party `probe-rp` (6);
  which console actions send one (LA1, measured on Keycloak 26.8.1: a user signed in to the client
  `probe-logout-actions`, which carries HopIn's ruled settings (#254, #506),
  `backchannel.logout.url` `http://probe-rp:8000/backchannel-logout`,
  `backchannel.logout.session.required` `false` and `use.refresh.tokens` `true`; a sign-out as control runs first and the probe
  fails unless its logout arrives; then disable user, delete user and remove group membership, one
  line each: logout seen, no matching logout observed within `Probe.logout_timeout_seconds` for a token
  whose `sub` is the user's, or action failed when the admin call did not succeed; the answer
  describes Keycloak's behaviour, not HopIn's erasure, which hopin#79 S4 owns); and
  none of the credentials it made or received (secret files, passwords, the TOTP seed, the relying party's secret, every
  token of every token response, each client secret and its tokens, and the admin console's PKCE
  verifiers, authorization codes and session cookies) in the `Config.Env` of any container it ran,
  in any compose, apply or service log output, or in its own output (7); the realm settings as decided, with admin events that carry no client
  representation (8). Proof 1
  fetches the login and account pages through the edge entrypoint and holds when both link a 200 resource under
  `/resources/<version>/{login,account}/hallucinai/` and the login page speaks German for
  `Accept-Language: de` (with a language switcher) and English for `fr` or none. Proof 3c
  runs the realm observer (`realm-observer`, #66) around an apply and holds when it lists exactly
  the console changes to declared objects that the apply resets (a mapper on the scope `groups`,
  a step in `browser-mfa-forms`, a subflow under `direct-grant-mfa-totp`, a default scope and a
  flow binding override on songmaker, a client role on its service account, hopin's service account
  turned off, which the apply turns on again with its scope, user and role mappings; the blockquote in docs/keycloak.md after „Theme and language“ states the class) and the
  console subgroup with its member, flows, role and group on service accounts, and the default
  scope on `agent-service` (a client without scope lists) are still there; proof 3d holds that a changed YAML which drops a group, a client
  and the realm role `agent-workload` deletes none of them nor the role's mappings; proof 9 checks the
  observer's container (65534, read-only, the keycloak network alone, its secret a file), an
  escaped line for a group named with ESC and a newline, that SIGINT and SIGTERM, sent as its
  container runs and as its inventory arrives, leave no container, and that an exit 0 carries
  the whole inventory (a stopped `compose run` exits 130 and may leave part of one on stdout;
  a signal it takes as the container begins to run may be lost, and the observe completes), and
  `does not answer` with Keycloak stopped. Proof 8 also asserts the two themes, the locales and
  the master's untouched theme and language. Proof 10 signs a member of the app's group
  (`/apps/songmaker/admin`, `/apps/hopin`, `/apps/presentator/admin`) in to each of the
  songmaker, hopin and presentator clients through the edge entrypoint with PKCE, its secret a scratch file the
  overlay mounts; the token response has a refresh token for each of the three. The overlay names all three back-channel networks `<project>_backchannel_*`, so the probe never creates a `hal_*` network. For each of the three it also drives the agent workload cells of #183
  (W1 to W3: the `client_credentials` token has `agent-workload`, the `agent-service` audience, `azp`
  and the realm's token lifespan or 1 s more, with no client override; a person's token has no `agent-workload`; proof 10 also puts the person in `/services/agent-service/subscription` and requires that group, as a full path, in the access token beside the `agent-service` audience) and `agent-service` with every flow off (W4); DG1 (#297) shows that only songmaker starts a device sign-in and only with its secret. Proof 11 (#129) loads
  `keycloak/go-live` and runs only its step 6 (never `run()`, whose compose calls would reach the
  operator's project): the admin it creates holds `admin` with `CONFIGURE_TOTP` and
  `webauthn-register` pending (both enabled in master), is refused a password grant without TOTP,
  meets the TOTP enrolment and then the passkey page at the browser sign-in, and a second run asks
  nothing and adds no user. Its typed password joins proof 7's sweep, and master's admin events
  are off. Passkey registration itself is not driven. Proof 12 (#242) drives the realm step of
  `hal apply` (`hal.stack.realm.reconcile`) against this stack: its Compose, a repository of the realm
  files, and `hal` (from the checkout's `.venv` or the PATH) under a scratch HOME with its
  own `apps.toml` for this stack's Keycloak database. It holds that a first step backs up, proves
  the restore of that snapshot and applies, and a second plan is quiet and its step makes no
  snapshot; that a changed `realm.yaml` applies with lines equal to the YAML diff; that a tampered
  import-checksum attribute (what a restored database would show) is applied again; that a console
  mapper on `groups` is listed as reset to the file with the snapshot; that a failing
  config-cli ends the step partial with the way back and is planned again; that a changed
  `entrypoint.sh` plans the step; and that a group, a client and a top-level flow made in the
  console survive a step that runs, are listed as only in Keycloak with no removal line, and the
  unread kinds are named on one line (#248). Proof 3a also holds that the freshly imported realms
  list nothing only in Keycloak and hold every pinned built-in, so a Keycloak upgrade that adds or
  drops a built-in fails it. Proof EV2 (#181) signs in, sends a wrong
  password and logs out through the edge entrypoint, sending `Forwarded` the way Cloudflare's
  rule sets it (`external/cloudflare.tf`) next to a forged `X-Forwarded-For`, and holds when the
  user's stored events are exactly one LOGIN and one LOGIN_ERROR, both with exactly the
  `Forwarded` address, a wrong password from an IPv6 address stores that address, and the logout
  stores none. The probe simulates the rule; it does not prove that Cloudflare applies it (#190).
  Cells P1 and TC1 to TC6 (#775) run in proof 10, for songmaker first: the required action
  `TERMS_AND_CONDITIONS` is enabled, default and has the declared priority (P1); a user made through the admin API carries it,
  one made with `Admin.create_user` does not (TC1); the sign-in meets the terms page after the password, with title, text and
  link as the theme's message files say, in German for `Accept-Language: de` and in English for none, with Accept and Decline
  (TC2); Decline ends in `access_denied` with no session and no stored time (TC3); Accept stores the time as Unix seconds,
  which an admin reads and the account REST, both tokens and an admin PUT do not show or change (TC4); a later
  sign-in to hopin and presentator asks nothing (TC5); asked again, Decline removes the old time and Accept stores a new one (TC6).
  Cells SP1 to SP6 and SP8 (#837) also run in proof 10: hopin's workload token carries the `speech-service` audience
  only when it asks for `speech-service-audience`, and `speech-workload` either way, as its service account's role (SP1, SP2); a
  member's person token carries the audience only when asked and `/services/speech-service` either way, as the default `groups`
  scope gives it, and its ID token never the audience (SP3); a non-member's token without the scope carries no audience (SP4); songmaker and presentator are refused the scope and
  never get the audience (SP5); `agent-service` and `speech-service` are bearer-only with every flow off (W4, SP6); the group has no subgroup (SP8).
  Cells F0, U3, U4, RF0 to RF2 (#844) run last in hopin's branch of the same proof, on a target, a scope copied from `speech-service-audience`, a role and two clients the probe makes: the probe holds the setup and prints, as measured and not held, what a workload token's `aud` and roles are under Keycloak's defaults, without the default roles, with `fullScopeAllowed` off and with a role scope mapping (U3), and what refreshes and a new authorization request give sessions signed in before and after the scope turned optional (U4, RF1, RF2); `docs/keycloak.md` states the answers for the pinned Keycloak.
- `hold` brings the same stack up, runs no proof and keeps it for another repository's proof.
  It seeds nothing beyond the realm's `songmaker`, `hopin` and `presentator` clients, which callers must not create
  themselves; they create their other clients and users through the admin API. A hallucinai user created there carries
  `TERMS_AND_CONDITIONS` pending, so its first browser sign-in meets the terms page (#775).

## Exit codes, stopping and cleanup

`run` ends with `PROBE PASSED` (exit 0) or `PROBE FAILED: <what>` (exit 1); exit 2 refuses an
argument (`--scratch` must be a new or empty directory). Under the `timeout` wrapper Ctrl-C never
reaches the probe, so stop it with `kill -TERM` on the probe. A SIGTERM or Ctrl-C stop of `run`
ends with exit 1 and a finished teardown.

The lock is held for at most 770 seconds: at 720 `timeout` stops the probe, which still tears down
(exit 124), and 50 seconds later it kills the probe and its teardown (exit 137). After an exit 137
or a `teardown: stack edge-kc-probe FAILED` line, remove the project under the lock, from a
directory without a compose file, because Compose finds its containers, networks and volumes by the
name:

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM \
        timeout -k 30 300 docker compose --project-name edge-kc-probe down --volumes --remove-orphans

This command is itself the teardown: its K of 30 seconds covers compose's own stop.

## `hold` contract

Progress lines (`stack: ...`) go to stdout. Read stdout until a line starting `READY ` and parse
the rest as JSON:

    READY {"admin_url": "http://localhost:<admin port>", "edge_url": "http://127.0.0.1:<edge port>", "realm": "hallucinai", "public_issuer": "https://auth.hallucinai.de/realms/hallucinai", "admin_client_id": "config-cli", "admin_client_secret_file": "<scratch>/secrets/config-cli-secret"}

The line holds a path, never a secret value. Get an admin token with `client_credentials`, the
client id above and the secret read from that file, against
`<admin_url>/realms/master/protocol/openid-connect/token`. The ports differ on every run; read
them from the line.

Keep stdin an open pipe (`subprocess.PIPE`). `hold` blocks until SIGTERM, SIGINT or EOF on stdin;
any of them after `READY` is a normal stop: teardown runs, `teardown: stack ... removed` prints,
then `HOLD ENDED`, exit status 0.

Exit 1 with `PROBE FAILED: ...` when the bring-up fails, when a signal arrives before `READY`, or
when the teardown leaves the stack behind (after `READY` too).

Callers pin edge by commit SHA and require a clean checkout of it.

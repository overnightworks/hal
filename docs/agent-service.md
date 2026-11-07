# The agent service

Reference and runbook for the operator and for an engineer changing the agent service. The code is
the truth: `compose.yaml` (the `agent-service` service, its `agent-songmaker`, `agent-presentator`, `agent-hopin` and `mcp` networks),
`agent-service/service.toml`, `agent-service/image/` (the image recipe), `agent-service/live_canary.py` and the probes under `probe/agent-service/`. The egress gateway of LiteLLM is in
[internal-ca.md](internal-ca.md); the platform picture is [architecture.md](architecture.md).

## The image

`agent-service/image/` is the recipe of the service's image (agent-runtime, Claude Code
`2.1.302`, Codex `0.163.0`; the pins are in the Dockerfile and `requirements.txt`). Every byte that enters it is
pinned: the base image by digest, the Python packages by hash, each CLI by its sha256 and its reported version (Codex as its release archive, whose one executable the Dockerfile unpacks by name). A
wrong hash fails the build, and so does a CLI that does not report its pinned version; a build that
fetches also fails on a changed or vanished artifact. The image is never pulled from a registry, because its
name could be anyone's on a public one (`pull_policy: never`), so it is built on the PC.
`agent-service/setup` builds it when it is missing, and `hal apply` asks to run that setup before it
switches the unit on. The build line it runs, from the repository root:

```sh
docker build -f agent-service/image/Dockerfile -t edge-agent-service:0.12.0-claude-2.1.302-codex-0.163.0 agent-service/image
```

A release bump runs `python3 scripts/agent_service_lock.py <tag>` (it needs `git` and `uv`), the
only writer of `requirements.txt`. A bump of either CLI changes its pin in the Dockerfile and its
`version` in `service.toml`; every bump changes the image name, which carries the release and both CLI
versions, in `compose.yaml` and in the build line above together. A base-image digest bump alone keeps
the name, so setup builds nothing.

## The service

`agent-service` (profile `agent-service`) is that image with `agent-service/service.toml`: one
container, one worker, no published port. It runs as `1000:1000` with `init`, a read-only root, no
capability, `no-new-privileges`, no core dump and `restart: unless-stopped`; `/tmp` (its `HOME`) and
the working root `/run/agent-service/cli` are size-bounded tmpfs mounts owned by 1000 with mode 0700
(the service refuses to start on a working root that is not owned by its user with exactly that
mode), all `nosuid,nodev,noexec`. The unit `agent-service` of `fleet.yaml` is switched off
(`enabled: false`): `hal apply` stops and removes its container, and a switched-on unit starts only the service. A missing image or login directory stops the start
(`pull_policy: never`, `create_host_path: false`), so apply reports the unit partial and never on. A missing signing key or CA root file is
asked of its unit's setup first (`agent-service/setup`, `step-ca/init`); a file still missing after the
setups, such as the root while `step-ca` is off or stopped, refuses `hal apply` before its `yes`,
naming the path and `next: hal setup`, with nothing switched.

It signs for songmaker's origin, `https://songmaker.mcp.internal`, the name `traefik-mcp` answers to on `mcp`, which it joins
beside the per-app agent networks (never `mcp-songmaker`). The key reaches it as the compose secret
`agent_service_signing_key`, the one file `~/.secrets/agent-service/signing/private.pem` and never its folder, read through
`[signing] key_file`; the step-ca root reaches it as `step_ca_root_certificate` through `[mcp] ca_file`, because the service
trusts that file alone and ignores `SSL_CERT_FILE`. A file secret binds the inode, so a new key reaches the service only
through a recreate. The service alone decides an agent's model: `[defaults] model` (`anthropic/opus`), which
an app or an agent entry of `service.toml` may override, and the request names none (a body with `model`
answers 422). `run_started` names the model and the route the service chose.

The service admits no background run, and which identity runs an app's background agents is agent-runtime#479's question.

A change to `compose.yaml` or the image reaches the running service through `hal apply`: its plan
names the recreate, which ends every run in flight, and the one `yes` covers it. A change to
`service.toml` alone is not seen by apply yet (the file is bound from the checkout), so it still
needs the hand recreate
`docker compose --profile agent-service up -d --force-recreate agent-service`, in the live checkout
after `hal update`.

## The login

The service runs the Claude CLI under the operator's subscription, with the one token that
`claude setup-token` prints, in one file inside a read-only directory bind:

```
~/.secrets/agent-service/              0700
~/.secrets/agent-service/claude/       0700, uid 1000   (bound at /run/agent-service/login/claude)
~/.secrets/agent-service/claude/token  0600, uid 1000, one line
```

`agent-service/setup` makes it, in the operator's terminal and after `hal apply` has asked: it creates
the directories with 0700, narrows a too-open token file to 0600, and when the token is missing or
refused it asks the operator to run `claude setup-token` in another terminal and paste its token, then
an empty line. `claude setup-token` prints the token across line breaks, so the paste runs up to that
empty line and its lines are joined (`hal.output.hidden_paste`, the reader the secrets wizard uses
too); text after the empty line, a line at the terminal's 4095-byte limit or lines that cannot be one
token are refused. Text that arrives only after the paste was read is not part of it and stays in the
input for the shell. The paste is read without echo, judged by the reader's rules as the exact bytes
to write, and only then written to `token.new` (created 0600) before the rename over `token`. A refused paste leaves the old token
as it was; the folders are opened without following a link and locked for the swap.
`agent-service/setup --check` changes nothing and says the first gap. The token is pasted only
there, never on a command line or in an issue. The file is a regular file of at most 16 KiB with one line, the token: no JSON,
no API key (`sk-ant-api…`), nothing group or others can touch. The service refuses to start
otherwise, naming `cli.anthropic.token_file` and the path, never the content. `hal secrets -v` lists
the entry `agent-service-claude`.

A second login, for Codex, lives beside it in `~/.secrets/agent-service/codex/auth.json`
(folder 0700, file 0600), bound at `/run/agent-service/login/codex` the same way, but read-write: the
service renews this login itself, so it needs the directory to create `.auth.json.new` and rename it
over the file (a read-only directory logs `sibling not created` hourly and nothing renews). It is the
service's one writable bind. The start refuses an incomplete sign-in or a file that group or others
can touch, naming `cli.openai.token_file` and the path; a Codex run gets a copy without the renewal
token. A stop waits for a renewal in flight, so `stop_grace_period` in `compose.yaml` covers about 45 s
for the renewal plus at least 60 s beyond it; a kill sooner can leave `.auth.json.new` behind.
`agent-service/setup --check` does not check it: a missing folder fails the start. It is a
separate login with its own refresh token, so it never shares the operator's `~/.codex` and never
rotates it away. `hal setup` walks the operator through that browser login when the file is missing (a link at
`auth.json` counts as missing) and
leaves a present one untouched; that is also the way to sign in again, once the file is gone. Because the
service can write the folder, `codex login` never runs in it: hal runs it with `CODEX_HOME` at a fresh
private folder beside it, moves only a regular `auth.json` (0600) into the folder, replacing whatever
stood there without following a link, and removes the rest, however the login ends. hal never reads or
prints the file. `hal secrets -v` lists the entry `agent-service/codex`; every file in the folder besides
`auth.json` and the service's `.auth.json.new` is an unknown file there.

**Why 1000:1000.** The service's reader refuses a login file that group or others can touch, so the
container user must own the directory and the file. 1000 is the operator's uid on this PC, so his
own `claude setup-token` writes a file the container can read. Another uid needs its own renewal
procedure, which is not covered here. It is a deployment choice, not the reader's requirement.

**Renewal.** `agent-service/setup --renew` takes a new paste, writes it to `token.new` beside the
old one and swaps the name (an atomic rename); the next run opens the file anew, without a restart. The bind
is the directory, never the file: a file bind (or a compose `secrets:` file) would keep the old
inode, and the rename would never reach the running container. A missing directory fails the start
instead of becoming a root-owned one; the directory itself stays for ever, so never replace or
re-create it.

## The signing key

The service signs the capability of every admitted app-tool run with one RSA-3072 key; the app's
verifier (songmaker-web) checks it against the public half. The service never makes the key
(agent-runtime `docs/operations.md`, "App tools"); only `agent-service/setup` does, in the operator's
terminal after `hal apply` has asked:

```
~/.secrets/agent-service/signing/              0700, uid 1000
~/.secrets/agent-service/signing/private.pem   0600, uid 1000, one unencrypted PKCS#8 PEM block, at most 16 KiB
~/.secrets/agent-service/signing/public.pem    0644, uid 1000, the SPKI half `openssl pkey -pubout` derives
```

**The contract.** Setup makes the pair with the host's `openssl` (version 3), and key bytes travel only
over pipes: never on a command line, never in a printed line. Every path is reached without following a
link, under one lock on the folder, and nothing is ever written through a link. `private.pem` is created
exclusively (`private.pem.new`, then `link(2)`, which refuses any existing entry). A plain run and
`--renew` never replace an existing key. A missing public half is derived again, and a public half with
another mode is set to 0644. Setup refuses, in one line that names the file and the next step, a pair
it cannot use, and changes nothing, `--renew` and the token included (the key is judged first):

- a private key that is malformed, encrypted, of another size or exponent, failing openssl's own key
  check, or missing while `public.pem` is still there, or a public half that is malformed or not its pair: the line names
  `agent-service/setup --replace-signing-key`;
- a wrong owner, a mode other than 0600 or a link: the line asks for the operator's own fix, because setup
  never narrows or unlinks those.

`agent-service/setup --check` changes nothing and exits 0 for a sound pair, 1 for the first gap, a
refusal or a leftover of an interrupted run, and 2 when openssl or the host cannot answer; an openssl that exits 1 on a key counts as refusing it
only when it passes the same check on a throwaway key. A leftover (`*.new`, `*.next.pem`) beside a
sound pair is cleared by the next plain run; beside a missing or unusable pair only the `*.new` of an
interrupted creation is, and the `*.next.pem` wait for `--replace-signing-key`. A temporary entry that
is a link, no regular file or not the service's is never unlinked. `hal secrets -v` lists both files; a public half at 0644 is no finding.

**Replacing the key.** `agent-service/setup --replace-signing-key` is the one command for a planned
rotation, for a key that may have leaked, and for a lost private key (there is no backup: the key protects
no stored data). It works only at a terminal, says what it does, and goes on after a typed `yes`. The old
private key's directory entry is removed by the rename; the blocks are not erased. The stages:

| Stage | State | What holds |
|---|---|---|
| R0 | the new pair is being made (openssl fails, the new key fails its check, an interruption) | the active pair is unchanged, or still missing; running containers are unaffected; run the command again, or plain setup to clear leftovers |
| R1 | interrupted between the two renames | the new private key sits beside the old public half: `--check` says so and plain setup refuses; the service still signs with the old key it read at startup, and songmaker-web still trusts the old one, until the service is recreated, then calls fail with 401; the old pair is gone, so run the command again |
| R2 | both renamed, nothing recreated | `--check` is 0, but the old key still signs and is still trusted: a compromise is not recovered yet |
| R3 | one container recreated | every tool call fails with 401 until the other is recreated |
| R4 | both recreated | done once a new capability verifies against the new `public.pem` and every songmaker-web container was created after it |

The command ends by naming the two recreates: agent-service with `python3 agent-service/live_signer.py`
while songmaker-web is not on the network (otherwise as in "The service"), then
songmaker-web with songmaker's own deploy command. A file bind keeps the old inode, so only a recreate
reaches a container, never a restart. There is no grace period.

## What a turn leaves behind

The service has no writable persistent mount but the Codex login directory (a renewal rewrites `auth.json` there, nothing a turn leaves). The CLI's per-run home and work directories and `/tmp`
are tmpfs ([The service](#the-service)), which the kernel may page to swap, and a restart or recreate
drops them. The only host binds are `service.toml` and the two login directories, read-only except the Codex
login directory, which the service renews ([The login](#the-login)), and the two read-only file secrets ([The service](#the-service)); the Claude login reaches the CLI only through its environment. The service sets
no `logging` override, so its logs follow the Docker daemon's settings; their destination and
retention are set there, not in this file (log retention: edge#167,
<https://github.com/overnightworks/edge/issues/167>). What the service itself keeps of a run is
stated in agent-runtime's section
[What a run keeps](https://github.com/overnightworks/agent-runtime/blob/main/docs/wire.md#what-a-run-keeps).
The content of
a turn leaves this PC for Anthropic, which generates the answer.

**What the route logs depends on `[api] log_depth`** (`~/.config/hal/config.toml`, home.md
„Konfiguration“). At the default `metadata` a call leaves these records, none with its content except a provider's
error text, which may quote part of a request and is logged word for word:

- **The front's access line**, one JSON line per request on its standard output: start time,
  client address (the app's network), method, router (the route), service, its and LiteLLM's
  status, both durations. Every header and the path are dropped, so no bearer and no query.
- **LiteLLM's error line**, at `ERROR` in JSON, for a refusal or a failure only: an unknown app
  key logs `Invalid proxy server token passed` with the key's hash, a provider's refusal its
  class (a 401 is `litellm.AuthenticationError`) with the provider's error text word for word,
  as the operator ruled; OpenAI's 401 names the key masked to 3 + 4 characters, and a provider
  that quotes part of a request puts that part in the line and the row below. A served call logs no line,
  and a bearer that is no virtual key (not `sk-…`) is refused with 401 without a line of its own.
- **A spend log row** per call with a valid app key, a failure at the provider included (`LiteLLM_SpendLogs`): the key's hash and
  alias, the person's fingerprint, model, tokens, cost, times, status and a failure's error;
  never the prompt, answer or picture (`store_prompts_in_spend_logs: false`). LiteLLM deletes a
  row, and the tool index it feeds, after 30 days (`maximum_spend_logs_retention_period`).
- **The person's fingerprint**, the ruled pseudonym, stands in that row and in no line: not in the
  front's, and not in LiteLLM's at `metadata` (a refused key, a refused plain bearer, both providers'
  refusals and a served call).

At `everything` LiteLLM logs at `DEBUG` with message logging on. Each request stands whole in LiteLLM's log, including its fingerprint. The fingerprint appears in that log and its spend row, never in the front's lines (probe L6); the front's line stays as above, so the one thing it does not show is the path and
query of a request the front itself refuses before LiteLLM sees it. `hal apply` passes the
depth's variables to Compose (`src/hal/stack/api_limits.py`), so a changed depth is a recreate of
`litellm`; without them compose.yaml's defaults are `metadata`'s. `probe/agent-service/litellm_logs.py`
drives both refusals, a served call and the switch on the fake-only stack, finds no prompt, answer,
bearer or whole key in any line or row at `metadata` and each fingerprint it sent only in the spend
rows, and drives LiteLLM's cleanup (period 1h, interval 5 s) against a backdated row and its
tool-index row.

**The API route keeps no content at `metadata`, as evidence for the paths exercised only, except a provider's error text, which may quote part of a request and is logged word for word.**
LiteLLM logs no message and redacts the `Messages:` suffix of its exceptions, and neither it nor
the front configures a callback or cache; LiteLLM's database holds keys, budgets, tool names, each
person's fingerprint with its counters and the spend log rows above, but no prompt. What the
database keeps per person, per tool or per label in its other tables goes after 90 days without use
([The API route](#the-api-route), What expires).
The retention census (`agent-service/retention_census.py`, driven by
`probe/agent-service/litellm_retention.py` on the fake-only stack with hopin's key) searches its canaries in every writable mount and every log of
the front, the gateway, LiteLLM and its database, the database's volume among them, and in a `pg_dump` of the database, naming the table a
hit sits in. The canaries sit in the message, the tool description, the tool-call arguments, the tool result, the answer, a streamed
answer, `User-Agent` and `x-litellm-tags`. After a success, an upstream 500, a refused
model, a refusal of LiteLLM's guard, a tool call and a streamed answer it finds none, and each search is proven by a control that plants
a canary where it must be found; an upstream error body that echoes the request lands in LiteLLM's error line and the call's spend log row alone. The tool names
also land in the daily tool spend, which holds no fingerprint, and in the spend log's tool index,
whose request id joins to the spend row, so for its 30 days a tool name is attributable to the
fingerprint. The front's constant user agent lands in the tool rows, beside each tool name. LiteLLM writes no request
tag from the user agent (`disable_add_user_agent_to_request_tags`), so a conforming request writes no tag row. A key holder who does not
conform can send a tag in the body: a root `tags` list, `metadata.tags` and `litellm_metadata.tags` each land in `LiteLLM_DailyTagSpend`
with LiteLLM's own request id and in the call's spend log row, and so in the database's volume, in no other table, log or mount, and `metadata` as a JSON string lands
in no sink at all; none reaches the provider. The daily label rows are in the
tables `hal expire` prunes, so the 90 days above cover them; the spend log rows go with their 30 days. `logging.lastResort` and
`warnings.warn` reach LiteLLM's standard error too, and whether a real path sends request content
through them is not measured. Memory holds the content
while a run is in flight, and tmpfs may be paged to swap. The Docker log driver's retention is the daemon's
(edge#167); the census proves that no content reaches the logs, a provider's error text excepted, not how long they live. Any other
path is not covered by this.

**The metadata lines are apart from the content.** The service and the front write an access line
per request, LiteLLM an error line per refusal by an unknown key or failure at a provider (none for a plain bearer), and the gateway keeps no access log:
its TCP routers have none, and whether Traefik can log a TCP connection there is not measured.
Their retention is the Docker daemon's (edge#167). How long Anthropic keeps the content is stated in the
privacy section, which owns it.

**Whose account.** Only the operator and his own test accounts are members of `/services/agent-service/subscription`, so his
Claude subscription serves only his own use. Every other person reaches the provider only through the
API route, under Anthropic's commercial API terms: an app's own key at LiteLLM, not the service
(see „The API route“). No app takes that route yet. The privacy section `agent-dienst` in
`legal/sections/litellm/datenschutz.html` describes only that route as an app takes it, through the
front, LiteLLM with its database and the gateway to Anthropic: what a request carries, what LiteLLM keeps
per app and per person, when that is deleted, how long the backup keeps it and the legal basis of the budget per person (Art. 6 Abs. 1 lit. f DSGVO, with the right to object in the general part). The Keycloak section states the same backup bound for a snapshot before an update. hal writes it itself
(operator, 03.11.2026, [#110](https://github.com/overnightworks/hal/issues/110)); by the operator's ruling
of 28.10.2026 ([#299 comment](https://github.com/overnightworks/hal/issues/299#issuecomment-6464712955))
it does not speak of the subscription, which no user can ever use, and no
text a person reads speaks of the subscription. Every other app or service links
`/datenschutz#agent-dienst` and says in its own text only what it sends. Who may use the subscription is decided by the service's subscription group, and who may
use the API route by LiteLLM's keys and budgets, the same in every app; an app adds no AI group of its own. Membership in the app (`/apps/<name>`) stays separate access to the app.

## An app's side

An app reaches the service by joining its own agent network, `hal_agent_<app>` (`hal_agent_songmaker`,
`hal_agent_presentator`, `hal_agent_hopin`), as an external network. The names are fixed, so the project's rename does not
move them, and no app sees another's network:

```yaml
services:
  app:
    networks: [default, agent]
networks:
  agent: {external: true, name: hal_agent_songmaker}
```

and calls `http://agent-service:8080` (the service's own default port; the smoke uses it). No CA mount is needed: the service is plain http on an isolated internal network, and no
host process can reach it, because the network has no host address and publishes no port.

An app that calls LiteLLM directly holds only its own key, the file `~/.secrets/litellm/apps/<app>` (`songmaker`,
`hopin`, `presentator`). `hal setup` creates a missing one with the prefix `sk-` that LiteLLM requires of a custom
key, mode 0644 in a 0700 folder so the app's container reads it as its own user. `hal apply`'s key step reads it to
make the app's key in LiteLLM (see "The API route"); hopin's file is also read by `agent-canary`, the live canary's one-off. On the same agent network the app posts to
`http://litellm-front:4000/v1/chat/completions`, a picture to `http://litellm-front:4000/v1/images/generations`, and lists its models with `GET http://litellm-front:4000/v1/models`, with that key as bearer; the unit `litellm` starts the front.

## The API route

An app reaches the providers through LiteLLM with its own key: Anthropic for text, OpenAI for
pictures. The path starts on the app's own
agent network, `hal_agent_<app>`, and is `litellm-front`, `litellm`, `agent-egress`, the provider,
over the internal, isolated networks `litellm-backend` and `litellm-egress`; `litellm` also reaches its own Postgres, `litellm-db`, over
`litellm-db`, a network with those two members. The unit `litellm` of `fleet.yaml` runs the front,
LiteLLM, its database and `agent-egress`. While the unit is on, `hal apply` makes each app's key, the person budget
and the admin budget with its customer rows (the key step below).

- **The boundary.** `litellm-front` is the same pinned Traefik as the gateway with three routers,
  `POST /v1/chat/completions`, `POST /v1/images/generations` and `GET /v1/models`
  (`agent-service/litellm/front/`); every other method and path, `/v1/images/edits`,
  `/v1/images/variations` and `/v1/models/<name>` included, ends in the front itself, so
  LiteLLM's own unauthenticated routes are unreachable. An app key's `GET /v1/models` lists
  exactly the key's `models`; past its budget it is refused with 422, at no spend. Behind it
  LiteLLM's own keys decide, with no hal code in its process: a request needs an app key as
  bearer (401
  otherwise), a model among the key's `models` (the three
  names `text/opus`, `text/sonnet`, `text/haiku` and the picture name `image/flare` of
  `config.yaml`, which maps to OpenAI's `gpt-image-2.5-flare` on the key `litellm/openai`; 403
  otherwise), a path among
  the key's `allowed_routes` (403 otherwise, the provider routes `/v1/messages` and
  `/v1/completions` included), and a `user`, the person's fingerprint (`enforce_user_param`; 401
  without one), which LiteLLM sends on to Anthropic as `metadata.user_id` and to OpenAI as `user`. The privacy text rests on the client v0.20.0, pinned from its git tag (`pyproject.toml`): the fingerprint is `person_fingerprint`, a SHA-256 of issuer and subject, the same in every app, and the gateway backend sends the app's key as the only bearer, the fingerprint in the body's `user`. LiteLLM also routes
  by a `model` in the query string, which the key's `models` do not bind: one unknown to
  `config.yaml` is refused with 400, but a configured name outside the key's `models` is served by that model and its spend counts on the key, and a key or person
  past its budget is refused (measured). The front therefore answers any query string on its
  routes itself with 400 and no `Location`, so nothing of such a request reaches LiteLLM. It sets
  `User-Agent` to one constant, `litellm-front`, and removes `x-litellm-tags`, which LiteLLM would
  turn into request tags; the bearer and `Content-Type` pass unchanged.
  LiteLLM's ban list refuses `api_base` in the body with 401, and a fallback naming a URL with 401
  too. Messages are
  not logged; LiteLLM needs a master key to boot, a file secret that no app holds (`hal setup`
  makes it, see below; LiteLLM and the key step read it), so its admin routes stay closed to apps,
  straight at `litellm:4000` too.
- **The money.** Each app key carries `max_budget` in dollars and `budget_duration` `1mo`; LiteLLM
  prices each answer by its cost map and refuses the next request of a key past its budget before
  the provider, with 422 `budget_exceeded`, never the 429 agent-runtime's client reads as busy
  (`budget_exceeded_status_code` stays unset). A person's spend across all keys is bounded by the
  budget that `max_end_user_budget_id` in `config.yaml` names, refused the same way; a row LiteLLM
  makes for a new fingerprint resets with that budget. A fingerprint whose own row links a budget
  without `max_budget` is bound by its app key's budget alone: the rows of the members of the
  Keycloak group `/services/litellm/admin` link the admin budget `litellm-admin`, which has no
  `max_budget` and the person budget's `1mo`, so their spend resets with it. The periods reset on the 1st
  of the month at 00:00 UTC, through LiteLLM's own reset job. A recreate keeps the refusals: spend
  lives in the database. Without its database a running proxy keeps admitting a cached key until
  its cache expires (about a minute, measured), then refuses every request before the provider
  with 503. The operator sets both amounts in `~/.config/hal/config.toml` and `hal apply` writes
  them (the key step, below): a changed app budget binds the key at its next request, a changed
  person budget once LiteLLM's cache lets it in (up to 60 s per cache layer, two layers read; 44 s
  in one measured run). A budget below the spend refuses from then on, until the reset, and the
  plan does not warn.
- **The key step.** `hal apply` makes each app's key and the person budget from the numbers of
  `[api]` and `[api.<app>]` in `~/.config/hal/config.toml` (`docs/home.md`, „Konfiguration“): per
  number an app's own table, else `[api]`, else the code default in `src/hal/stack/api_limits.py`.
  The defaults are per app 10 dollars and 5 parallel, and 2 dollars per person; every key carries
  `1mo`, the three routes, `models` as LiteLLM's `/v1/models` lists them and no rpm or tpm, and the
  app's name as `key_alias`; the person budget carries `1mo` under the id `max_end_user_budget_id`
  names. `hal apply`'s door reads the file before any guard and ends 2 on a malformed one; the
  step plans only what the file and LiteLLM's rows disagree on, so a changed number is a change
  row with old and new, and the next apply sets it without a recreate. An `[api.<name>]` naming no
  app the one-off read ends `hal apply` with `cannot plan` before the question while LiteLLM runs:
  a table for an app compose does not mount yet stops the setups that run would offer, and a
  retired app's leftover table stops every `hal apply` until the operator removes it. While the
  step does not read (below) the name is not checked and nothing is set. The apps are the
  key files compose mounts into the one-off `litellm-keys` (profile `apply`, on `litellm-backend`
  alone), which holds them and the master key; hal's own process opens neither. At plan time the
  one-off reads each app's live key by the SHA-256 of its file, in a request body, so a deleted key
  reads as absent and is made anew; the diff is plan rows under `litellm`, part of the one
  question. After the yes, past the realm step and before the apps, it makes the changes: the
  person budget first, then the apps in name order, each with only its changed fields, so a pure
  limit change keeps the period's reset. The first failed write stops the step: the result names
  it and every change not made, and the run ends `partial` with `next: hal apply`. An app whose
  name another live key holds (its file was replaced) is a `!` row before the yes; nothing is
  written for it, and the run ends `partial` naming it, which no hal command resolves (deleting the
  old key is the operator's call). Keys that cannot be read while LiteLLM runs end as an unread
  realm does: alone, `error:` and `next: hal apply` without a question; beside other changes,
  skipped and `partial`. Output names apps, budget ids and models, never a key or its hash. The
  step reads while the unit is on and the run neither starts LiteLLM nor recreates it or its
  database. Such a run's plan says `keys later` and the next apply checks them, so a first start
  takes two applies. While the unit is off or switched off the step does nothing. A file of the
  one-off that is missing refuses the run before the yes, with `next: hal setup`. After `hal setup`
  writes a new master key, the running LiteLLM still holds the old one and the step's read ends
  `keys not read`: `hal stop litellm`, then `hal start litellm`, and the next apply reads.
- **A start of LiteLLM.** It migrates its database before it listens; meanwhile the front answers
  502 and the key step reads nothing. A changed image of `litellm` or `litellm-db` is recreated
  after LiteLLM's proven pre-apply snapshot, as `docs/stack.md` "Images" says; the snapshot's restore
  test refuses a store with no key, and then nothing is recreated. `litellm-front` keeps its old
  image and is named `!`. A switch-on after a removal takes the same snapshot first. A change of
  `config.yaml` or `start.sh` alone does not recreate it.
- **The admin group's rows.** After the apps the step makes `litellm-admin` and links to it exactly
  the customer rows of the direct members of `/services/litellm/admin`, read at each plan through
  the realm observer's members mode; each fingerprint is `person_fingerprint` of agent-runtime's
  client, from the realm's issuer and the member's id, checked as `fp-` and 64 lowercase hex. A
  member's row is made, or linked when it is unlinked or linked to another budget; a row on
  `litellm-admin` that is no member's is unlinked, before any link; no other row is touched, so a
  row linked to another budget by hand stays linked. LiteLLM's update cannot clear a link, so an
  unlink deletes the row and makes it again from a read taken right before, with its own fields and
  its spend, the current month's; a lost answer between the two calls, or a remake LiteLLM refuses
  (a `default_model` gone from the router), loses that row and its month spend. The plan counts the
  rows linked and unlinked, never which. With Keycloak's unit off or switched off the rows are
  held, a row says so, and the run ends as it would. With the members not read (Keycloak not running
  at plan time, started by this run, the read failing, or the group absent) the rows stay and the run
  ends `partial` naming Keycloak with `next: hal apply`, exit 3, also when nothing else changes; an
  apply whose realm step makes the group, or which starts Keycloak, ends so. The members'
  fingerprints pass through hal's memory and the one-off's standard input and output; no printed
  line carries a fingerprint or a member, failures included.
- **The output default.** Each text name sets `max_tokens` 16384 in `config.yaml`: what a request that
  names none gets, and the output LiteLLM reserves against a budget, so the ceiling of a conforming
  app. An app that names more is bound by the budgets alone. The picture name sets none and sends
  no `quality`, so OpenAI's default holds; nothing is reserved, and LiteLLM books a picture's cost
  from the answer's `usage`, so one picture can pass a budget and an answer without `usage` books
  nothing.
- **The database.** `litellm-db` is Postgres 17 at the image and hardening of `keycloak-db` (one
  `x-postgres` anchor in `compose.yaml`), with its own volume and the file secret `litellm/db-password`,
  which `start.sh` turns into `DATABASE_URL`. It holds the keys (their hashes only), the budgets, and
  each person's fingerprint with its counters; the weekly backup copies it whole, and
  `hal restore litellm --live` loads a snapshot back while LiteLLM is switched off, so a lost
  volume gets its month's spend back ([backup.md](backup.md), „Restore LiteLLM“). LiteLLM stays the official image by its digest: BerriAI ships one
  image whose enterprise part a licence key switches on, and hal sets no key and uses no enterprise
  function, so it builds no image of its own. It runs with no `LITELLM_LICENSE` and none of the settings behind its premium check (`enforced_params`,
  `allowed_ips`, global `allowed_routes`, key `tags`, `model_max_budget`, `/key/regenerate`). It
  waits for the database to be healthy at the start only; with the database gone or the password
  wrong it ends non-zero after Prisma's retries. The database password is an environment value
  of the proxy and its Prisma processes, the same holders as the provider keys.
- **What expires.** `hal expire`, run daily at 04:00 by `hal-expire.timer` (`Persistent=true`
  catches up a missed run), deletes in one statement, all or nothing, the daily person, tool and label
  rows (`LiteLLM_DailyEndUserSpend`, `LiteLLM_DailyToolSpend`, `LiteLLM_DailyTagSpend`) dated more than 90 UTC days back, the tool
  rows (`LiteLLM_ToolTable`) not used for 90 days, and the customer rows (`LiteLLM_EndUserTable`)
  whose fingerprint has had no request for 90 days and whose spend is 0. A customer row linked to
  a budget, as an admin's is, stays, and so do keys, budgets and every other table. The period is
  `RETENTION_DAYS` in `src/hal/litellm_expiry.py`, not a setting, because the privacy text states
  it. The run prints counts only; with `litellm-db` not running it deletes nothing and exits 0. A
  deleted row stays in the backup's snapshots as long as [backup.md](backup.md), „What a backup
  holds, and its limit“, states, and a restore brings it back until the next daily run deletes it
  again. A failed run fails `hal-expire.service`, which `hal check` and `hal alarm` report as `job-failed`; its error line says `nothing deleted` only
  when psql reported the failure, and otherwise that the outcome is unknown and the next run repeats
  it. `probe/agent-service/litellm_expiry.py` proves it on the fake-only stack; re-run it on every
  LiteLLM bump, since a schema change shows in production only as a failed unit.
- **What stays reachable.** The front sees every message and every app key in memory; a
  compromised front could spend credit through LiteLLM, bounded by each key's budget and parallel
  bound. The front is a member of every app's agent network, so an app could give itself the alias
  `litellm` there; the front therefore finds LiteLLM through
  `extra_hosts` at its fixed address on `litellm-backend` (`compose.yaml` pins the subnet, and its
  `ip_range` keeps that address from any other container), never by Docker's DNS. The service shares
  those app networks with the front but sends it nothing, and has no address on `litellm-backend` or
  `litellm-egress`. LiteLLM reaches
  only the front, its database and, through the gateway's `litellm` entrypoint, the providers'
  names.
- **The bound.** Each app key's `max_parallel_requests` bounds its requests in flight; LiteLLM
  refuses the next one at once with 429 and `Retry-After`, before the provider, and another key's
  requests are not counted against it. The operator sets it per app through `config.toml` (the key
  step); a changed bound binds at the key's next request, and 0 refuses every request. It counts
  HTTP requests, not runs, per LiteLLM process in memory (a second worker or replica would multiply
  it). A request whose client left keeps its slot until the provider call ends or 3600 s pass
  (`cancel_on_disconnect` is off and `config.yaml` sets no `request_timeout`), so stalled calls can
  refuse a key for up to an hour.
- **A change reaches LiteLLM only through a recreate** of its container: `config.yaml` (model
  remapping included) and `start.sh` are read once at start, and the four secrets (the two provider
  keys, master key, database password) are files mounted at create time. Keys and budgets live in the
  database and change without a recreate.
- **A provider failure reaches the caller.** An upstream reset, a broken answer and Anthropic's
  refusal of a used-up balance (a 402 `billing_error`, or a 400 saying the credit balance is too
  low) each reach the provider once, and the caller gets an error, never a 200; LiteLLM's error
  line and the call's spend log row name the provider's error, so the logs tell them apart. A caller that leaves
  does not end the request in flight, which may finish and is billed.
- **Rotating a provider key is a recreate.** A replaced provider key file reaches LiteLLM only
  through its recreate, until then it keeps sending the old key. Compose refuses to create LiteLLM's
  container when a provider key file is missing; an empty one makes the container exit non-zero
  with a line that names the path only.
- **What `hal setup` makes.** The master key `~/.secrets/litellm/master-key` and the database
  password `~/.secrets/litellm/db-password` come from `hal setup` alone: it generates each (a
  `service-password`, never shown) and creates only a missing file.
- **Proof:** `probe/agent-service/litellm.py` runs the whole path on a fake-only stack (its
  docstring gives the command line): the fake Anthropic sits on `internet`, made
  internal, and the probe refuses to start otherwise. Its caller is a throwaway on HopIn's agent
  network that posts agent-runtime's wire body with an app key the probe made through the master
  key; `litellm_apps.py` puts one fake app with a key of its own on each app network and proves
  that each reaches the front alone and that an app's alias `litellm` captures nothing.
  `litellm_admission.py` drives the key's models, the budgets, the person budget, the operator's
  exception and the bound, `litellm_failures.py` the failure and key cases,
  `litellm_retention.py` the retention census of the route and `litellm_live_canary.py` the live canary, both with hopin's key made by
  the key step, `litellm_keys.py` the key step through
  `hal apply`'s own plan and run, and that LiteLLM calls no provider from its start to the first app
  call (S0), `litellm_limits.py` the operator's numbers from `config.toml` through that step, and
  `litellm_backup.py` the backup, its restore test and a lost volume, on the same
  stack and with the same caller; `litellm_wheel.py` runs the model list and one tool turn of hal's
  own client wheel through the route on that stack. `litellm_unit.py` drives the copy's real `hal apply` with the
  shipped unit `litellm`: its first start and the second apply, the refusals of a missing file, the
  switch-off and the stop that hold the key step, the recreates that make it wait, a start after a
  failed one and the way on after a new master key. Re-run them for every LiteLLM,
  Traefik or Docker bump. The CI job `front` runs the front's table of requests
  (`tests/test_litellm_front.py`) for every Traefik bump; a LiteLLM bump still needs the probes.

## Proofs

Re-run the probes in `probe/agent-service/` for every Traefik, Docker, agent-runtime or LiteLLM upgrade.
`litellm_keys.py` proves `hal apply`'s key step on the fake-only stack: its plan and run, a lost answer,
a pure limit change, a taken name, a failed write and a deleted key, and that no key or hash reaches an
argument, the step's input or output, or LiteLLM's log; and the admin group's rows with the members as
scenario data: the links and the unlink, the refusal of a former admin past the person budget, the
monthly reset, the members not read, and that no printed line carries a fingerprint or a member. It runs
in hal's environment, which holds the agent-runtime client. Cell LM1 of the Keycloak probe proves the
members mode against a real Keycloak. `litellm_limits.py` proves the numbers of
`[api]` and `[api.<app>]` through that step: their precedence, their return to the defaults, no
recreate and no moved reset, an app budget below spend, a bound and a budget of 0, a person budget
below spend binding within LiteLLM's cache lifetime, and an app table naming no app.
`litellm_backup.py` proves `hal backup litellm`,
its pre-apply snapshot and `hal restore --test litellm` under a scratch HOME, that the dump holds every
table and no key in clear, and that a lost volume rebuilds through the key step with budgets at zero.
Its load cells prove `hal restore litellm --live`: only while LiteLLM is switched off, a key and a
person past their budgets still refused after a load into the rebuilt volume, a failed load that
changes nothing, the question's no and the missing terminal, a killed run's load that runs to its
own end, and an interrupt that waits for the load.

**The live canary** is `cd ~/srv/hal && python3 agent-service/live_canary.py`, for the operator at the go
to let people in; it has not been run. It makes a paid call from hopin's app budget, so it runs only when the operator says so,
after `hal apply` has made hopin's key. No one signs in: it checks that the front, the gateway, LiteLLM and its database each run once
(C0), runs `agent-canary` once, which posts a random value to the front with hopin's key, the way an app does, and asks for it back (C1),
waits 34 seconds, the longest interval of the writers a request feeds, and runs the retention census over those four containers for that value (C2), a `pg_dump` of the database among
the sinks. The dump reads the whole store into the program's memory and never leaves it. Each run leaves one customer row for its throwaway
fingerprint, which `hal expire` removes like any other. Nothing is recreated; a failed canary ends the run, and a new run uses a new value.
It prints only verdict lines of a closed grammar and a last line, `canary and census held` or `canary and census FAILED`, matching the exit
code; no exception text, key or container output reaches the terminal. The probe `probe/agent-service/litellm_live_canary.py` runs it
against the fake-only stack.

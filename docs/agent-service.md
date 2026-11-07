# The AI route

Reference for the operator and for an engineer changing the AI route: what a call leaves behind, an app's side, the API route through LiteLLM and the probes. The code is
the truth: the LiteLLM route, `agent-service/live_canary.py` and the probes under `probe/agent-service/`. The egress gateway of LiteLLM is in
[internal-ca.md](internal-ca.md); the platform picture is [architecture.md](architecture.md).

## What a call leaves behind

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
while a call is in flight. The Docker log driver's retention is the daemon's
(edge#167); the census proves that no content reaches the logs, a provider's error text excepted, not how long they live. Any other
path is not covered by this.

**The metadata lines are apart from the content.** The front writes an access line
per request, LiteLLM an error line per refusal by an unknown key or failure at a provider (none for a plain bearer), and the gateway keeps no access log:
its TCP routers have none, and whether Traefik can log a TCP connection there is not measured.
Their retention is the Docker daemon's (edge#167). How long Anthropic keeps the content is stated in the
privacy section, which owns it.

**Whose account.** Every person reaches the provider only through the API route, under Anthropic's commercial API terms: an app's own key at LiteLLM (see „The API route“). No app takes that route yet. The privacy section `agent-dienst` in
`legal/sections/litellm/datenschutz.html` describes only that route as an app takes it, through the
front, LiteLLM with its database and the gateway to Anthropic: what a request carries, what LiteLLM keeps
per app and per person, when that is deleted, how long the backup keeps it and the legal basis of the budget per person (Art. 6 Abs. 1 lit. f DSGVO, with the right to object in the general part). The Keycloak section states the same backup bound for a snapshot before an update. hal writes it itself
(operator, 03.11.2026, [#110](https://github.com/overnightworks/hal/issues/110)). Every other app or service links
`/datenschutz#agent-dienst` and says in its own text only what it sends. Who may use the API route is decided by LiteLLM's keys and budgets, the same in every app; an app adds no AI group of its own. Membership in the app (`/apps/<name>`) stays separate access to the app.

## An app's side

An app reaches `litellm-front` by joining its own agent network, `hal_agent_<app>` (`hal_agent_songmaker`,
`hal_agent_presentator`, `hal_agent_hopin`), as an external network. The names are fixed, so the project's rename does not
move them, and no app sees another's network:

```yaml
services:
  app:
    networks: [default, agent]
networks:
  agent: {external: true, name: hal_agent_songmaker}
```

An app holds only its own key, the file `~/.secrets/litellm/apps/<app>` (`songmaker`,
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
  `ip_range` keeps that address from any other container), never by Docker's DNS. LiteLLM reaches
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
  low) each reach the provider once, and the caller gets an error, never a 200. The router keeps no cooldown,
  so the next call goes to the provider again and gets its own answer, never a 429; LiteLLM's error
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

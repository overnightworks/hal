# The agent service

Reference and runbook for the operator and for an engineer changing the agent service. The code is
the truth: `compose.yaml` (the `agent-service` service, its `agent-songmaker`, `agent-presentator`, `agent-hopin`, `egress` and `mcp` networks),
`agent-service/service.toml`, `agent-service/image/` (the image recipe), `agent-service/live_smoke.py`,
`agent-service/live_signer.py` and the probes under `probe/agent-service/`. The egress gateway it leaves through is in
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
the name, so setup builds nothing. `probe/agent-service/image.py` builds with `--no-cache` (the CLI files are served by digest) and starts the
entrypoint from the clean image.

## The service

`agent-service` (profile `agent-service`) is that image with `agent-service/service.toml`: one
container, one worker, no published port. It runs as `1000:1000` with `init`, a read-only root, no
capability, `no-new-privileges`, no core dump and `restart: unless-stopped`; `/tmp` (its `HOME`) and
the working root `/run/agent-service/cli` are size-bounded tmpfs mounts owned by 1000 with mode 0700
(the service refuses to start on a working root that is not owned by its user with exactly that
mode), all `nosuid,nodev,noexec`. The unit `agent-service` of `fleet.yaml` starts it with
`agent-egress`: `hal apply` brings both up. A missing image, login directory, signing key or CA root stops the start
(`pull_policy: never`, `create_host_path: false`, and a compose file secret that has no source), so apply reports the unit partial and never on.

It signs for songmaker's origin, `https://songmaker.mcp.internal`, the name `traefik-mcp` answers to on `mcp`, which it joins
beside the per-app agent networks and `egress` (never `mcp-songmaker`). The key reaches it as the compose secret
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
refused it asks the operator to run `claude setup-token` in another terminal and paste the line, which
is read without echo, judged by the reader's rules as the exact bytes to write, and only then written
to `token.new` (created 0600) before the rename over `token`. A refused paste leaves the old token
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

**Renewal.** `agent-service/setup --renew` takes a new pasted line, writes it to `token.new` beside the
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

## The API credential

The API route's bearer is one service credential that `litellm` checks and, once the route is on,
the service sends. Only `agent-service/setup` makes it, in the operator's terminal after `hal apply`
has asked:

```
~/.secrets/agent-service/api/                   0700, uid 1000
~/.secrets/agent-service/api/credential.json    0600, uid 1000, UTF-8 JSON, only the field shared_key, at most 16 KiB
```

**The contract.** The file is what agent-runtime's reader accepts (`docs/operations.md` of
agent-runtime): UTF-8 JSON with only `shared_key` and/or `app_keys`, no duplicate field, `app_keys` an
object, every value of the credential syntax. The rules live once on the hal side, in
`agent-service/litellm/gate.py` (`shared_key_of`), and setup judges the bytes it read through them,
so `--check` never says "set up" for a file the hook refuses. A missing credential is made with
`secrets.token_urlsafe(32)` through `credential.json.new` (created exclusively), then `link(2)`,
which refuses any existing entry. Every path is reached without following a link, under one lock on
the folder. A plain run and `--renew` never replace a credential, and nothing is printed of it. Setup
refuses, in one line that names the file, and changes nothing, `--renew` and the token included:

- a credential the reader refuses (larger than its 16 KiB, not UTF-8 JSON, an unknown or duplicate
  field, `app_keys` not an object, a value outside the syntax): the line names
  `agent-service/setup --replace-api-credential`; a file within the limit is judged whole;
- a wrong owner, a mode other than 0600, a link or no regular file: the line asks for the operator's
  own fix, because setup never narrows or unlinks those. A file setup may not open is judged by its
  owner first; only one of the right owner that still cannot be read is a host failure (`--check`
  exits 2).

`agent-service/setup --check` changes nothing and exits 0 for an accepted credential and 1 for the
first gap, a refusal or a leftover `credential.json.new`, which the next plain run clears.
`credential.next.json` waits for `--replace-api-credential`.

**Replacing the credential.** `agent-service/setup --replace-api-credential` works only at a terminal,
says what it does and goes on after a typed `yes`. It writes `credential.next.json`, checks it with
the reader and renames it over `credential.json`; the old key is not erased from the disk. It ends
by naming the recreates: `litellm`, and `agent-service` as well while `service.toml` has an `[api]`
table. Both containers read the file at create time, and the old credential gets 401 at LiteLLM
after its recreate, so the order is LiteLLM first. A lost credential needs no backup: it protects no
stored data.

The master key `~/.secrets/litellm/master-key` is not made here: `hal setup` generates it (a
`service-password`, never shown) and creates only a missing file.

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

**Whose account.** Only the operator and his own test accounts are members of `/services/agent-service/subscription`, so his
Claude subscription serves only his own use. Every other person reaches the service only through the
API route (`/services/agent-service/api`), under Anthropic's commercial API terms. That route is not
enabled yet (`api_groups` and `[api]` are unset in `service.toml`), so a member of the api group
gets 403 `not_enabled`. An app's privacy text therefore describes only the API route. Which groups
may use an AI feature is decided by the service's subscription and api groups only, the same in
every app; an app adds no AI group of its own. Membership in the app (`/apps/<name>`) stays separate
access to the app.

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

and calls `http://agent-service:8080` (the service's own default port; the smoke and the unit probe
use it). No CA mount is needed: the service is plain http on an isolated internal network, and no
host process can reach it, because the network has no host address and publishes no port.

## The API route

A person who is in an API group but not in a subscription group reaches the provider through
LiteLLM instead of a CLI. The path is `agent-service`, `litellm-front`, `litellm`, `agent-egress`,
the provider, over the internal, isolated networks `litellm-api`, `litellm-backend` and
`litellm-egress`. Nothing runs it yet: the profile `litellm` is in no unit, and `service.toml`
has no `[api]` table.

- **The boundary.** `litellm-front` is the same pinned Traefik as the gateway with one router,
  `POST /v1/chat/completions` (`agent-service/litellm/front/`); every other method and path ends in
  the front itself, so LiteLLM's own unauthenticated routes are unreachable. LiteLLM's hook
  (`agent-service/litellm/auth.py`, deciding in `gate.py`) allows that one route with the service
  credential as bearer, no query string, the body sent as exactly `application/json` (LiteLLM also
  parses form bodies), no `x-litellm-` header (LiteLLM reads per-request retries and timeouts from
  them), no `anthropic-` header (LiteLLM forwards `anthropic-version` and `anthropic-beta` to the
  provider) and exactly the body keys `model`, `messages` and `tools`, which agent-runtime's one posting
  function sends. LiteLLM has no database and no limiter and
  messages are not logged; it needs a master key to boot, a third file secret that `hal setup`
  generates and no client holds, so its admin routes stay closed.
- **What stays reachable.** The front sees every message and the service credential in memory; a
  compromised front could spend credit through LiteLLM, bounded by the prepaid credit. The API
  route has no concurrency cap until agent-runtime#634. LiteLLM reaches only the front and, through
  the gateway's `litellm` entrypoint, the provider's name.
- **A change reaches LiteLLM only through a recreate** of its container: `config.yaml` (model
  remapping included), `auth.py`, `gate.py` and `start.sh` are read once at start, and the three
  secrets (provider key, master key and service credential) are files mounted at create time.
- **A failure ends the run by name.** LiteLLM, the front or the gateway stopped, an upstream 500,
  529, timeout, reset or broken answer, an untrusted certificate, a refused credential and
  Anthropic's refusal of a used-up balance (a 402 `billing_error`, or a 400 saying the credit
  balance is too low) all end the run as `failed: provider_unavailable` on route `api`;
  the run never falls back to the subscription. A used-up balance therefore looks like an outage
  until the operator checks his credit. A cancelled run ends `cancelled` and starts no further provider
  request; the cancel does not close the request in flight, which may finish and is billed.
- **Rotating a key is a recreate.** A replaced provider key file reaches LiteLLM only through its
  recreate, until then it keeps sending the old key. A replaced service credential reaches each
  reader only through its own recreate, LiteLLM first, then `agent-service`; in between every run
  fails `provider_unavailable`. Compose refuses to create LiteLLM's container when the provider
  key file is missing; an empty one makes the container exit non-zero with a line that names the
  path only.
- **Proof:** `probe/agent-service/litellm.py` runs the whole path on a fake-only stack (its
  docstring gives the command line): the fake Anthropic and a fake issuer sit on `internet`, made
  internal, and the probe refuses to start otherwise. Re-run it for every LiteLLM, Traefik or Docker
  bump. `probe/agent-service/litellm_failures.py` drives the failure, key and rotation
  cases on the same stack. The CI job `front` runs the front's table of requests (`tests/test_litellm_front.py`) for
  every Traefik bump; a LiteLLM bump still needs the probe.

## Proofs

Re-run the probes in `probe/agent-service/` for every Traefik, Docker, agent-runtime or LiteLLM upgrade.

**The live smoke** is one command, run in the live checkout after `hal apply` and with the image
built: `cd ~/srv/hal && python3 agent-service/live_smoke.py`. It signs you in as yourself (the
`songmaker` client's device grant, edge#184 D6): it prints a link and a code and opens the link
where a browser is there; you sign in and confirm on any device, and the run goes on by itself,
nothing is pasted (it waits as long as the code lives). Keycloak starts a
device sign-in only for a request with songmaker's client secret, which lives in `~/.secrets` on
this machine, so no stranger can send you a link to confirm; no other client allows the grant.
It recreates the service and runs the live cells L2-L7, L9
and E6-E10, E12 against it, which its docstring lists; E3-E5 and E10's packet windows stay with the
probe's `egress.py`. L3 holds when `run_started` names `anthropic/` and a model of `[cli.anthropic] models` on route `cli`, and shows both. L9 holds when no
JWT-shaped string is in the smoke output, `docker inspect` or the service log. It needs the image, the client's secret file and the login token under
`~/.secrets`, and the person in the groups `/apps/songmaker` and `/services/agent-service/subscription`.
The realm declares these groups but grants no membership: add yourself once in the admin
console on port 8090. The smoke names the possible causes of a refusal for rights. Run it at once, as
the workload token lives five minutes, and send the head its report.

**The live signer proof** is `cd ~/srv/hal && python3 agent-service/live_signer.py`, run by the operator
after a key change or a change of the service's gateway route. It signs you in as the live smoke does,
recreates the service and judges the recreate (L3): the service's networks are the resolved ones and each is internal and
isolated, and its two secret mounts come from `private.pem` and `root_ca.crt` under `~/.secrets`, as the compose
configuration names them. It then removes the shared `hal_agent` network, which no compose file defines any more, once it
has no member (found by its compose labels, never by name); with a member it prints FAILED and removes nothing. Then it
runs `agent-smoke --tool` twice, with no paid turn: both runs fail before any CLI starts. L4a, with no backend behind the gateway, holds when the run ends `failed` with no text and the
service log shows the gateway's refusal. L4b joins a stand-in, `mcp_signer.py` in the service image with only
`public.pem` mounted read-only, at songmaker-web's place on songmaker's MCP network, and holds when the
capability it receives verifies against `public.pem` (signature, `kid`, `aud`, the one tool, the Host
`songmaker.mcp.internal`); the stand-in is removed afterwards. Only the verdict is printed, never the
capability. It needs `[apps.songmaker] mcp_origin` in `service.toml`. It also refuses once anything but traefik-mcp is on songmaker's MCP network; from then on
songmaker's own call is the proof.

**The login command** is `python3 probe/agent-service/cells_12b.py --login-directory DIR`; its docstring gives the
full command line (the probe-stack lock and a timeout). It starts the service in a throwaway project with `DIR` bound read-only as the
login, a stand-in issuer, the bootstrapped entrypoint and `max_parallel_cli_runs = 1` in a scratch
`service.toml` only, and holds agent-runtime#440's A1d conditions there (`config`, U2, U3, U6, U7, U8, and I6
against the container's own image), the S00 census of every writable mount and S1, the no-token cell. It
refuses before starting anything unless the resolved compose configuration binds exactly that
directory and that scratch file read-only. It prints only verdicts, counts, role names and a docker verb
with an exit code, and an exact-secret gate over its output is the second line. Agents give it only a `mktemp`
directory with a dummy token.

Between S00 and S1 it drives R2 (agent-runtime#440 B9 (a)-(e)), only when every frame cell held. The fake app
(`app_tools.py`, in mode `hold`) holds a call of `step` until its connection closes. One run is posted once by
`run_client.py` in `agent-smoke`, which prints only a closed vocabulary of lines; the host writes `close` on
the client's stdin when the app logs the held call, or, when no call came within the time bound, writes it then
and ends the wait.
`tree_census.py`'s `watch` mode samples the CLI group and the run tree every 10 ms, the client reads
`GET /runs/{id}` and the host the service log. B9 (a)-(e) and an observed timing line, with no bound claimed, follow. A
dummy login makes no call: B9 (a)-(e) are then NOT DRIVEN ("no call reached the fake app") and the command
exits 1 by design. With the real login R2 is one paid model turn, which is why it is posted once and `busy` is
not retried.

**The unit probe** is `python3 probe/agent-service/unit.py --scratch DIR`; its docstring gives the full command
line (the probe-stack lock and a timeout). It starts the real service in a throwaway project
with a dummy login of each CLI and drives the cells U1 to U11 and U15, which its docstring and code define: the
process, the container hardening, the tmpfs and login mounts, a replaced login of either CLI seen at once, and the
refusals (bad working-root mode, missing login directory, login at the wrong mode, no token, a Codex sign-in
without its access token). P09 and P11a are the
signing key's: a key at mode 0640 or 0000 stops the start, naming `signing.key_file` and no key byte (a wrong owner needs
root and is not driven), and with the key or the CA root moved aside the service is not created and nothing appears at the
source. Every probe that starts the real service writes a throwaway CA and signing pair into its scratch HOME
(`scratch_secrets.py`).
U12 is `egress.py --target service`; U13 is the static facts in `tests/test_agent_service_unit.py`.
`--cell smoke` drives U14, the `agent-smoke` against the service with a stand-in issuer, U17, the
refusals before any run (the previous protocol: 400 `unsupported_version`, outside the app: 403 `forbidden`,
and the api group only: 403 `not_enabled`; there is no offer), and U16 runs
the cells of `live_smoke.py` there, past its sign-in: all hold except L2, which must fail with the
dummy login. L4 is proven only live, with the real login; the probe has no L4 cell.
`--cell containment` adds a fake app that lists tools on
`agent-songmaker`, certified by the scratch CA and named in place of songmaker's origin, and runs `agent-smoke --tool NAME:EFFECT` against it: B1 (the run with the relay
is accepted and fails at the upstream) and B2 (a capability written into a tool description fails
the relay's owner and the run) of agent-runtime#440. B2 (c) asserts that the runner's failure is
`CapabilityReflected`, that no run reaches `CliLoginRefusedError` and that no announcement verdict
other than `RELAY_NOT_CONNECTED` appears; a `RELAY_NOT_CONNECTED` line is tolerated. B3 to B5 run through a wrapper bound read-only in place of the CLI: it execs the CLI, and
on `-p` while the probe's flag file is there it first starts marker A in the CLI's process group and
marker B in a session of its own. B3 holds when, 6 s after the run's terminal frame, A is gone, the
working root lists nothing and B lives on under init (docs/host.md: a `setsid` process keeps
running); B4 kills the service's pid as its own user and holds when the container dies once and
restarts, B is on no host or container process list and the working root and `/tmp` are empty.
The processes and listings come from `tree_census.py` through `census_client.py`. B5 runs the smoke a hundred times in a row with the wrapper transparent, each run with
freshly minted tokens, and holds when afterwards only init and the same service process remain, the
working root is empty and `/tmp` is unchanged, the loopback listener count is unchanged, and the
service log holds exactly one runner line of `CliLoginRefusedError` per run and no other ERROR,
announcement refusal or bare line; another writable mount whose listing changed is only reported. B5 prints the first and last run id of the log, the shown names of the remaining processes and the before and after listings of the working root and `/tmp`; the `cc-socks` directory in `/tmp` is reported, not asserted.
For that the probe starts the service through a bootstrap that adds one WARNING-level root handler
with level and logger name (the same records the service prints bare otherwise), a deviation the
report names. The cells print counts and event names, never a log line. The loopback capture (the
(a) parts) is not driven: it is not built (#339).
`--cell signer` (`signer.py`) is the live signer proof without the live stack. It starts the service with the
scratch signing key, the scratch CA and songmaker's `mcp_origin` from `service.toml`, and a TLS front for that origin on `mcp`
(a Traefik of compose.yaml's pin, its certificate issued by the scratch CA). P12: a run naming one tool reaches the front
before any CLI start, and `mcp_signer.py` behind it verifies the capability against the scratch `public.pem`. P12b: with
no stand-in behind the front it answers 502, the run fails without text and no CLI starts, and the front saw no other host.
P28: two `--force-recreate`s of the service each start, and P12 holds again. P26: every compose call resolves only the
project's networks. It runs in the unit probe's throwaway project and prints verdicts, counts and names, never a capability.

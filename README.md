# edge

The gatekeeper in front of the tools on the operator's PC. Traefik listens on loopback only:
`127.0.0.1:8081` is the tunnel's target and routes `<name>.<EDGE_DOMAIN>` to the container that
carries the label `edge.name=<name>` (a container with `edge.alias` is routed under that second host too); `127.0.0.1:8090` serves the Keycloak admin console on this PC and
is never a tunnel target. Traefik never sees the Docker socket: a GET-only socket proxy hands it the
container list and events.

Nothing here is reachable from outside until the operator publishes it with `hal apply`, which puts
the catalog's hosts on the tunnel. `auth` goes live as `public` (see
[docs/keycloak.md](docs/keycloak.md)). There is no Zero Trust for now (operator, 20.10.2026); the
wildcard protection is X8b on overnightworks/edge#30. The platform picture (layers, services,
secrets, deploy, re-setup, operations, decisions) is [docs/architecture.md](docs/architecture.md).

## Start

The first `hal apply --local` writes `.env`, plans, asks to run each setup still missing (for example
`keycloak/go-live`, which itself starts the socket proxy and Traefik), asks `yes` and switches the
catalog's units on. Apply never starts a stopped core service, so Traefik and the socket proxy are
started by hand; `hal apply` then publishes, and `hal online` opens the tunnel, which `hal setup`
installs disabled. Readiness and stop are in [docs/stack.md](docs/stack.md).

```sh
hal apply --local
docker compose up -d --no-recreate socket-proxy traefik
hal apply
hal online
```

An entry of `fleet.yaml` with `repo` and `run` is an app. `hal apply` fetches the repository into
`~/srv/<key>`, shows its newest release tag (`vYYYY.MM.DD.N` on origin's default branch), and after `yes`
checks out the commit that tag named when it was planned, builds, starts it and waits for its health; the last successful
deployment is recorded in `~/.local/state/edge/deployed/<key>`. A newer tag is taken at the next
`hal apply`; there is no watcher. Your `yes` is the gate: whoever can put a tag on a merged commit
offers code to run here. No output of Compose is printed; run the failed step in `~/srv/<key>` to
read it ([docs/architecture.md](docs/architecture.md), sections 3 and 5).

## The commands

`hal` is the daily door of the workstation (`bin/hal`); `hal --help` lists its commands and
`hal <command> --help` shows one. Every command takes `-v`/`--verbose` for more detail where it
has some, ends with an exit code and prints errors as `error: <what>` with, where there is a way
on, one `next: <command>` line; the error form is `src/hal/output/__init__.py`, the exit codes are
in `src/hal/grammar.py`, the fleet rules for command lines are overnightworks/quality#80. Agents run
`hal stop` and `hal offline` only, never `hal apply`, `hal update`, `hal start` or `hal online`
([docs/architecture.md](docs/architecture.md), section 9). `hal rename OLD NEW [--dry-run]` moves a
renamed repository's clones on this PC, asks one `yes` before it moves, and ends 0, 1 (declined or
findings), 3 or 4 ([docs/naming.md](docs/naming.md), P1).
The five stack commands and `hal setup` deviate from the grammar
(Exception E in [docs/stack.md](docs/stack.md)); `hal setup` prints five rows, a verdict
and, when it stops, an `error:`/`next:` pair, asks one `yes` before it acts (`--dry-run` only shows), and ends 0, 1 (declined), 3 or 4 (no terminal).

## Adding a tool: the label rule

A container is routed when it carries both labels:

```yaml
labels:
  traefik.enable: "true"
  edge.name: grafana        # routed as grafana.<EDGE_DOMAIN>
```

- `edge.name` is one lowercase label, no dots, matching `^[a-z0-9-]{1,63}$` (`traefik.yml`); a
  container whose `edge.name` is missing or does not match is never routed.
- `edge.alias` (optional, one more host name of the same shape) routes a second host
  `<alias>.<EDGE_DOMAIN>` to a container that has `edge.name`; without `edge.name` it routes nothing.
- Traefik reaches the container by its bridge IP. If the container exposes more than one port, name
  it: `traefik.http.services.<name>.loadbalancer.server.port: "<port>"`.
- Never put a login-less tool on a network shared with a public tool.

## Threat model

Access protects every edge name except `auth`, which is public by design: there Traefik admits only
`/realms/hallucinai/`, `/resources/hallucinai/` and Keycloak's versioned static
`/resources/<5 characters>/`, so the master realm (its `/resources/master/` texts included), the admin
console, metrics and health never reach the tunnel. The bare `https://auth.<domain>/` answers 302 to
the hallucinai realm's account page. On the machine any process reaches any tool, the Keycloak admin
entrypoint included. The allowed container inspection is privileged read access and can expose
container environment values; review evidence must not dump those payloads.

## Where things live

`compose.yaml`, `traefik.yml` and `fleet.yaml` (the service catalog: which units run, and the
OpenTofu inputs) hold the stack; `dynamic/` holds routes for host processes and the emergency
barriers `hal stop` writes. `keycloak/` is the realms as code, `step-ca/` and `traefik-mcp.yml` the
internal CA and the MCP gateway, `agent-service/` the agent service and its egress gateway,
`legal/` the legal unit's frame and sections (imprint, privacy notice, terms; `hal apply` builds the pages into `legal/built/`), stylesheet and nginx config, `tunnel/` the cloudflared unit and its polkit rule, `backup/` the declared backups (their timers are declared in `src/hal/workstation/jobs.py`). The commands are Python under `src/` (`edge`, `hal`;
a bare `hal check` is the daily check (it also mails and pops up what is new), `hal check exposure` reports what reaches beyond loopback and `hal check hosts` compares Cloudflare with `fleet.yaml`, `hal backup` and `hal restore` run the backup runner; `bin/hal` is the launcher), the OpenTofu
root is `external/`, the probes that prove each service on a throwaway stack are under `probe/`, and
`tests/` holds the rest.

## Documentation

| Document | Holds |
|---|---|
| [docs/architecture.md](docs/architecture.md) | the platform picture, decisions, operations |
| [docs/stack.md](docs/stack.md) | run, apply, stop, catalog on and off, the emergency switch, rollback |
| [docs/external.md](docs/external.md) | Cloudflare as code (the publish phase of `hal apply`) |
| [docs/keycloak.md](docs/keycloak.md) | the login, the realm as code, go-live, upgrade |
| [docs/backup.md](docs/backup.md) | `hal check`, `hal backup`, `hal restore`, what a backup holds, restore |
| [docs/people.md](docs/people.md) | what an app offers so one person can be exported and erased |
| [docs/internal-ca.md](docs/internal-ca.md) | `step-ca`, `traefik-mcp`, `agent-egress` |
| [docs/agent-service.md](docs/agent-service.md) | the agent service: image, login, an app's side, proofs |
| [docs/home.md](docs/home.md) | `hal setup` and the workstation tools (German) |
| [docs/naming.md](docs/naming.md) | how every overnightworks repo, tool, package and unit is named |

## Checks

`.github/workflows/ci.yml` names each CI step by what it proves. Only the job `front` starts
containers: the pinned front of LiteLLM against a stand-in. The shared gate `quality / verdict`
follows (see `AGENTS.md`, "Checks").

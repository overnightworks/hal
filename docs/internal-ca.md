# The internal CA, traefik-mcp and agent-egress

Reference for the operator and for an engineer changing the MCP gateway. Three services, two
switches in `fleet.yaml`: `step-ca` (and with it `traefik-mcp`), and `agent-egress` (with the unit
`agent-service`). Their commands are `step-ca/init [--check]` and `hal apply`; the probes under
`probe/step-ca/` and `probe/agent-service/` hold the proofs. The recreate rules for the followers are in
[stack.md](stack.md); the platform picture is [architecture.md](architecture.md).

## Interne CA

`step-ca` is the certificate authority for the MCP origins: the servers behind `https://<app>.mcp.internal`
that the agent service calls over https only. It listens on `step-ca:9000` on the internal network `mcp-ca`
(no route out, no published port), has one ACME provisioner that accepts only `*.mcp.internal` through
TLS-ALPN-01, and issues 24-hour certificates. `step-ca/ca.json` is its one configuration. `traefik-mcp`
fetches its certificates from it.

**Go live, once,** as the operator (uid 1000): run `hal update`, then `hal apply`
(`services.step-ca.run.enabled: true` in `fleet.yaml`). `apply` makes no key material itself: while
`step-ca/init --check` fails it asks separately and, on `yes`, runs `step-ca/init` in your terminal,
re-checks, and shows a fresh plan.

**`step-ca/init`** makes the key material in one-off containers without a network and prints no secret.
It writes `~/.secrets/step-ca/` (directory 0700): `root_ca_key` (0600, never mounted into a running
container), `root_ca.crt` (0644) and `password` (0644, protects the root and the intermediate key). It
puts the intermediate and a copy of the root certificate into the `step-ca` volume and creates the empty
`traefik-mcp-acme` volume, so `apply` never creates one. A second run changes nothing; after an
interruption it completes what is missing and never overwrites a key. Back up `~/.secrets/step-ca/` and
the `step-ca` volume. The root certificate is what other services trust.

**Switching off.** `enabled: false` through a pull request, `hal update`, then `hal apply`; the CA and the
gateway go together, the volumes `step-ca` and `traefik-mcp-acme` stay, and switching on again serves the
same intermediate. `step-ca`, `traefik-mcp` and its helper `traefik-mcp-acme-owner` sit behind the
compose profile `step-ca`, so a plain `docker compose up -d` starts none of them. Removing the volumes or
`~/.secrets/step-ca/` throws the CA away; that stays a manual command, and the gateway must be off first,
since it holds certificates from this CA.

## traefik-mcp

A second Traefik, the gateway to the MCP origins. It has no host networking and no Docker API, and
listens on 443 inside internal networks, none with a route out: `mcp-ca` (step-ca and
`traefik-mcp`), `mcp` (`traefik-mcp` and the agent service), `mcp-backends` (`traefik-mcp` and the
probe's MCP server) and one network per app that serves an MCP origin, `hal_mcp_songmaker` for
songmaker (`traefik-mcp` and the app's web service, which joins it as an external network). It is the
only container on all of them. It answers to `<app>.mcp.internal` on `mcp-ca`
and `mcp`, gets a 24-hour certificate per name from step-ca over TLS-ALPN-01 (trusting only the CA's root,
`~/.secrets/step-ca/root_ca.crt`) and renews it by itself. `traefik-mcp.yml` is its static configuration;
`mcp/dynamic/` holds one router file per app (`hello.yml` is the probe's; `songmaker.yml` routes
`https://songmaker.mcp.internal/mcp`, the exact path, to `songmaker-web:8080` with the Host header
unchanged) and is watched. The
certificates live in the volume `traefik-mcp-acme`, which is not backed up because they are issued again.
Traefik reads `traefik-mcp.yml` only when it starts, so `hal apply` recreates `traefik-mcp` alone when
that file or its compose definition changed (rules in [stack.md](stack.md)). `traefik-mcp` waits for the
CA to listen, so the start order does not matter, also after a restart of the Docker daemon.

A new app adds its name to the `x-mcp-origins` list in `compose.yaml`, a router file under
`mcp/dynamic/` and a network of its own (`hal_mcp_<app>`, internal and isolated, joined by
`traefik-mcp` and the app's web service alone), so no app sees another's server. The name is
`<stem>.mcp.internal` ([naming.md](naming.md)).

**Proof:** `probe/step-ca/probe.py` starts a throwaway project under a throwaway `HOME` and holds the
proofs of the CA (init modes and silence, the ACME directory, no root key in the volume, restart and
partial-state behaviour) and of the gateway (reachable only with the root, 24-hour certificates, plain
http refused, the network split as ruled, songmaker's route (exactly `/mcp`, no other path or
name reaches the stand-in), no new host listener, renewal without restart, apply on and off
keeping both volumes, the emergency switch, setup asked by apply, the follower recreate rules). Its
compose calls run from a copy of `compose.yaml` whose fixed `hal_*` network names are moved into the
probe's project, and each checks first that it resolves no other network, so it never touches a live
one. It takes 13 to 20 minutes and, like every probe stack, runs under `/tmp/probe-stack.lock` with a time cap (its
docstring gives the command line). Re-run it for every step-ca or Traefik upgrade.

## agent-egress

A third Traefik, the one way out of the agent service: a TLS passthrough that reads the SNI of the
ClientHello and dials only `api.anthropic.com:443` (the provider CLI) and `auth.hallucinai.de:443` (the
JWKS fetch). It holds no key and has no API, ping or metrics. Any other name, or none, matches no router
and `sniStrict` ends the handshake in the gateway; `agent-service/egress/dynamic/allowed.yml` is the one
owner of the two names. The service finds the gateway through `extra_hosts` (`x-agent-attachments` in
`compose.yaml`), not through DNS: the networks `agent-songmaker`, `agent-presentator`, `agent-hopin`, `egress` and `mcp` (the anchor's five) are internal and isolated
(`gateway_mode_ipv4: isolated`), so a member has no route out, no host address and no DNS forwarding.
Only `agent-egress` sits on `internet`, a plain NAT bridge. It listens on two entrypoints, both TCP
and `:443`: `egress` (`172.31.252.10` of the network `egress`, for the agent service) and `litellm`
(`172.31.239.10` of `litellm-egress`, for LiteLLM). The router `provider` of `allowed.yml` is bound to
both entrypoints, `issuer` to `egress` alone, so LiteLLM reaches the provider and nothing else. The
three networks of the API route (`litellm-api`, `litellm-backend`, `litellm-egress`) are internal and
isolated like the others, and the exclusions between them hold: the service reaches LiteLLM only
through the front; LiteLLM reaches the front and, beyond it, only the provider's name on
entrypoint 2, and neither the service, entrypoint 1, the issuer, `mcp` nor the internet; the front
reaches LiteLLM, and the service's `litellm-api` address answers it. Like `traefik-mcp` it is a follower: its static file is bound at Traefik's static-config
path, so `hal apply` recreates it alone while the unit `agent-service` is on; no plain
`docker compose up -d` starts it.

**Proof:** `probe/agent-service/egress.py` (with `--target service` for the real service and a dummy
login) starts a throwaway project on a free /24 for each gateway network, never a live subnet, drives the cells
for allowed and refused names, observed through the packet windows of `probe/agent-service/capture.py`
each with a positive control, and removes everything. `probe/agent-service/litellm_network.py` proves
the exclusions of the API route on a fake-only stack, each with its control. CI holds the static facts in
`tests/test_agent_egress.py`.

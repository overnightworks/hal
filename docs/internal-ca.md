# The internal CA, traefik-mcp and agent-egress

Reference for the operator and for an engineer changing the MCP gateway. Three services, two
switches in `fleet.yaml`: `step-ca` (and with it `traefik-mcp`), and `agent-egress` (with the unit
`litellm`). Their commands are `step-ca/init [--check]` and `hal apply`; the probes under
`probe/step-ca/` and `probe/agent-service/` hold the proofs. The recreate rules for the followers are in
[stack.md](stack.md); the platform picture is [architecture.md](architecture.md).

## Interne CA

`step-ca` is the certificate authority for the MCP origins: the servers behind `https://<app>.mcp.internal`
reached over https only. It listens on `step-ca:9000` on the internal network `mcp-ca`
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
puts the intermediate and a copy of the root certificate into the `step-ca` volume (`edge_step-ca`) and creates the empty
`traefik-mcp-acme` volume, so `apply` never creates one. A second run changes nothing; after an
interruption it completes what is missing and never overwrites a key. Back up `~/.secrets/step-ca/` and
the `step-ca` volume. The root certificate is what other services trust.

**Switching off.** `enabled: false` through a pull request, `hal update`, then `hal apply`; the CA and the
gateway go together, the volumes `step-ca` and `traefik-mcp-acme` stay, and switching on again serves the
same intermediate. `step-ca`, `traefik-mcp` and its helpers `traefik-mcp-acme-owner` and
`speech-networks` sit behind the compose profile `step-ca`, so a plain `docker compose up -d` starts none of them. Removing the volumes or
`~/.secrets/step-ca/` throws the CA away; that stays a manual command, and the gateway must be off first,
since it holds certificates from this CA.

## traefik-mcp

A second Traefik, the gateway to the MCP origins and the speech service's one way to Keycloak's key
set. It has no host networking and no Docker API, and
listens on 443 inside internal networks, none with a route out: `mcp-ca` (step-ca and
`traefik-mcp`), `mcp` (`traefik-mcp` alone), `mcp-backends` (`traefik-mcp` and the
probe's MCP server). It is the
only container on all of them. Two more internal, isolated networks carry the key set (next section). It answers to `<app>.mcp.internal` on `mcp-ca`
and `mcp`, gets a 24-hour certificate per name from step-ca over TLS-ALPN-01 (trusting only the CA's root,
`~/.secrets/step-ca/root_ca.crt`) and renews it by itself. `traefik-mcp.yml` is its static configuration;
`mcp/dynamic/` holds one router file per app (`hello.yml` is the probe's) and is watched. The
certificates live in the volume `traefik-mcp-acme`, which is not backed up because they are issued again.
Traefik reads `traefik-mcp.yml` only when it starts, so `hal apply` recreates `traefik-mcp` alone when
that file or its compose definition changed (rules in [stack.md](stack.md)). `traefik-mcp` waits for the
CA to listen, so the start order does not matter, also after a restart of the Docker daemon.

### Keycloak's key set for the speech service

The speech service (`fleet.yaml`'s app `speech`) has no route out, so it fetches Keycloak's
key set from `https://keycloak.mcp.internal/realms/hallucinai/protocol/openid-connect/certs` and
trusts the CA's root, which reaches it as a compose secret. `traefik-mcp` answers to that name on
`hal_speech_issuer` (the speech service and `traefik-mcp` alone; the name is its only alias there)
and, through `x-mcp-origins`, on `mcp-ca` and `mcp`. `mcp/dynamic/keycloak.yml` routes exactly that
path, and nothing else of Keycloak, to `keycloak:8080` on `keycloak-keys`, a network of Keycloak and
`traefik-mcp` alone, so no MCP backend reaches Keycloak's port. Keycloak's address on `keycloak-keys`
is pinned and `traefik-mcp` finds it through `extra_hosts`, so an app on another of its networks
cannot answer as `keycloak` with a forged key set. Traefik routes by Host and SNI, not by network, so
the speech service reaches every router of `mcp/dynamic/`: `hello` (whose backend runs only in the
probe) and `keycloak`; none routes to the speech service.

The speech service's networks to its callers, `hal_speech_hopin` and `hal_speech_presentator`, are
internal and isolated, each joined by its app and the service alone. No running service of hal joins
them, and Compose creates only the networks of the services it starts, so the one-shot
`speech-networks` joins both and exits; `traefik-mcp` waits for it to complete, so the networks exist
whenever `step-ca` is on. The speech service's compose file declares all three as external, so it
does not start before they exist.

A rollback switches the speech service off first: `speech`'s `run.enabled: false` in
`fleet.yaml`, then `hal apply`, which removes its containers. Only then is the change reverted and
`hal apply` run again; reverted first, the fleet entry is gone and the speech containers stay
behind. The revert leaves the exited `speech-networks` container as an orphan: `docker rm` it. The
networks stay, inert, for callers that join them.

A new app adds its name to the `x-mcp-origins` list in `compose.yaml`, a router file under
`mcp/dynamic/` and a network of its own (`hal_mcp_<app>`, internal and isolated, joined by
`traefik-mcp` and the app's web service alone), so no app sees another's server. The name is
`<stem>.mcp.internal` ([naming.md](naming.md)).

**Proof:** `probe/step-ca/probe.py` starts a throwaway project under a throwaway `HOME` and holds the
proofs of the CA (init modes and silence, the ACME directory, no root key in the volume, restart and
partial-state behaviour) and of the gateway (reachable only with the root, 24-hour certificates, plain
http refused, the network split as ruled, no new host listener, renewal without restart, apply on and off
keeping both volumes, the emergency switch, setup asked by apply, the follower recreate rules). Its
compose calls and `step-ca/init` run from a copy of `compose.yaml` whose fixed network and volume names are moved into the
probe's project, and each checks first that it resolves no other network or volume, so it never touches a live
one. Most of its run is the wait for a renewal; like every probe stack, it runs through `probe-run` with its time cap (its
docstring gives the command line). Re-run it for every step-ca or Traefik upgrade.

## agent-egress

A third Traefik, the one way out of LiteLLM: a TLS passthrough that reads the SNI of the
ClientHello and dials only the text provider's and the picture provider's names on port 443. It holds no key and has no API, ping or metrics. Any other name, or none, matches no router
and `sniStrict` ends the handshake in the gateway; `agent-service/egress/dynamic/allowed.yml` is the one
owner of the names. LiteLLM finds the gateway through `extra_hosts` (`compose.yaml`), not through DNS: the networks
`litellm-backend` and `litellm-egress` are internal and isolated (`gateway_mode_ipv4: isolated`), so a member has no route out, no host address
and no DNS forwarding. Only `agent-egress` sits on `internet`, a plain NAT bridge. It listens on one TCP
entrypoint, `litellm` (`172.31.239.10:443` of `litellm-egress`), and every router of `allowed.yml` is bound to it. LiteLLM reaches the front
and, beyond it, only the providers' names; the front reaches LiteLLM. Like `traefik-mcp` it is a follower: its static file is bound at Traefik's static-config
path, so `hal apply` recreates it alone while the unit `litellm` is on; no plain
`docker compose up -d` starts it.

**Proof:** `probe/agent-service/litellm_network.py` starts a throwaway fake-only stack on free /24s, never a live subnet,
drives the cells for allowed and refused names, observed through the packet windows of `probe/agent-service/capture.py`,
and proves the exclusions of the API route, each with a positive control, and removes everything. CI holds the static facts in
`tests/test_agent_egress.py`.

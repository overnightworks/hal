# Speech probe

`probe.py` drives the speech app through H's edge copy (`probe/keycloak/in_copy.py`): it brings
H's stand up at the lane's base, installs the candidate with the speech app in the copy's fleet
and runs `hal apply --local`, beside the live stack. The app comes from a scratch origin of
speech-runtime whose newest dated tag carries the copy's network names (`release_origin.py`),
under a probe key, never the shipped key `speech-runtime`, whose project is the live app's.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \
        uv run --frozen python3 probe/speech/probe.py {transition|lifecycle} --scratch DIR

`transition` proves the upgrade (D5a/b, D2), the exposure and networks (D3, N1-N5), egress
(E1-E3), the key set through traefik-mcp (K1-K6), admission with the scratch Keycloak's tokens
(A1-A10, A12), step-ca switched off and on (S1) and the other traefik-mcp routers (M1).
`lifecycle` proves the app off and on (R1), the base files back (R2) and the missing networks
(D4). Each mode needs an existing, empty `--scratch`, runs H's cells H1-H6 around its own, and
ends with `PASSED: ...` (exit 0) or `PROBE FAILED: <what>` (exit 1).

Before every apply, `app_isolation.py` resolves the compose.yaml hal would start the app from
(the release at its tag, and the checkout once it exists) and refuses a route of the live edge,
a published port, a host namespace, the docker socket, a device or privilege, a source outside the
scratch HOME and any network but the copy's external `<project>_speech_*`; its negative cases
print one `self-check:` line each. The app's project is in every label sweep of the copy.

Tokens never leave the probe but on curl's stdin. The E2 cell starts an HTTP listener on every
host address for its own length, under `timeout 600`, its pid in the scratch. Where the host
drops container-to-host traffic for every bridge, its control (a container on the default
bridge) cannot reach the listener either: E2 then prints `E2 limit: ...` instead of holding,
the speech service's attempts must still all fail, and `gateway_mode_ipv4: isolated` is
proven by C1 (tests/test_traefik_mcp.py). hal withholds Compose's output, so D4 runs the app's
`docker compose create` by hand in its checkout, as hal's failure line asks, and reads only which
missing network it names. The first image build of the release takes about 12 minutes without a
build cache.

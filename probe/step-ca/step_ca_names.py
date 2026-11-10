"""The names the step-ca probe (probe.py) and its cell modules (mcp_networks.py, the songmaker
route, and traefik_mcp_follows.py) share: the compose project and file, the origins and their
URLs, the intermediate certificate's place and the curl exit codes the cells read."""

PROJECT = "edge-stepca-probe"
COMPOSE_FILE = "compose.yaml"
NOTHING_TO_CHANGE = "nothing to change"  # what `hal apply` says when it has no work
CA_URL = "https://step-ca:9000"
CA_HEALTH_URL = f"{CA_URL}/health"
CONTAINER_USER_ID = 1000  # the step user of the smallstep image
CONTAINER_USER = f"{CONTAINER_USER_ID}:{CONTAINER_USER_ID}"
CERTIFICATE_UNVERIFIED = 60  # curl exit codes
COULD_NOT_RESOLVE = 6
READY_SECONDS = 60
ROOT_CERTIFICATE = "root_ca.crt"
ROOT_IN_CLIENT = "/root.crt"
ORIGIN = "hello.mcp.internal"
ORIGIN_URL = f"https://{ORIGIN}/"
ORIGIN_ANSWER = f"Host: {ORIGIN}"  # the backend (whoami) echoes the request's Host header
# The backend speaks plain http by design, inside the compose network.
BACKEND_URL = "http://hello-mcp/"  # NOSONAR(S5332)
STEP_HOME = "/home/step"
INTERMEDIATE_CERTIFICATE = "certs/intermediate_ca.crt"
INTERMEDIATE_IN_VOLUME = f"{STEP_HOME}/{INTERMEDIATE_CERTIFICATE}"

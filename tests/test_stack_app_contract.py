"""What an app's compose file may contain (#255 B1-B4, B7 and the minimal contract), over the text
of the file alone."""

import pytest

from hal.stack import app_contract

KEY, TAG = "hopin", "v2026.10.22.1"
SERVICE = "restart: unless-stopped"
HEALTH = "healthcheck: {test: [CMD, 'true']}"
ROUTED = f'labels: {{edge.name: hopin, traefik.enable: "true"}}, {HEALTH}'


def service(*fields: str, routed: bool = False) -> str:
    return "{" + ", ".join(["image: x", SERVICE, *([ROUTED] if routed else []), *fields]) + "}"


def compose(*fields: str, routed: bool = False) -> str:
    return f"services: {{web: {service(*fields, routed=routed)}}}"


def refusal(
    text: str | None, hosts: tuple[str, ...] = (), served_elsewhere: frozenset[str] = frozenset()
) -> str:
    with pytest.raises(app_contract.ContractError) as refused:
        app_contract.check(text, KEY, TAG, hosts, served_elsewhere=served_elsewhere)
    return str(refused.value)


@pytest.mark.parametrize(
    ("text", "refused"),
    [
        (None, "none at the root of the repository"),
        ("services: [", "cannot be read (ParserError)"),
        ("just text", "must be a map with services"),
        ("services: {}", "must be a map with services"),
        (compose() + "\ninclude: [other.yaml]", "uses include (include)"),
        ("name: other\n" + compose(), "names its project other than hopin (name)"),
        (compose("profiles: [a]"), "service web uses profiles (profiles)"),
        (
            compose("extends: {file: x.yaml, service: y}"),
            "service web uses extends (extends)",
        ),
        (compose("extends: {service: y}"), "service web uses extends (extends)"),
        (compose("extends: y"), "service web uses extends (extends)"),
        (
            compose("depends_on: {db: {condition: service_healthy}}"),
            "service web waits for health or completion (depends_on condition)",
        ),
        (
            compose("depends_on: {db: {condition: service_completed_successfully}}"),
            "service web waits for health or completion (depends_on condition)",
        ),
        (
            compose("depends_on: {db: {condition: '${X:-service_healthy}'}}"),
            "service web interpolates a depends_on condition ($)",
        ),
        ("services: {web: image}", "service web must be a map"),
    ],
    ids=lambda case: str(case)[:40],
)
def test_a_compose_file_that_breaks_the_self_contained_rules_is_refused_naming_the_key(
    text, refused
):
    assert refusal(text).startswith(f"services.hopin: compose.yaml at {TAG}: {refused}")


@pytest.mark.parametrize(
    ("fields", "refused"),
    [
        ("ports: ['8080:80']", "service web publishes a port (ports)"),
        ("ports: ['${P}']", "service web publishes a port (ports)"),
        ("network_mode: host", "service web uses the host network (network_mode)"),
        ("network_mode: '${M:-host}'", "service web interpolates network_mode ($)"),
    ],
)
def test_b1_b7_a_published_port_or_the_host_network_is_refused_as_the_key_and_no_value_is_printed(
    fields, refused
):
    message = refusal(compose(fields))

    assert refused in message
    assert "8080" not in message
    assert "${" not in message


@pytest.mark.parametrize(
    ("labels", "refused"),
    [
        (
            None,
            "host hopin needs exactly one service labelled edge.name or edge.alias with it",
        ),
        ('{edge.name: other, traefik.enable: "true"}', "labels a name the entry does not list"),
        ("{edge.name: hopin}", "has edge.name without traefik.enable true (labels)"),
    ],
)
def test_b2_a_host_without_a_labelled_service_or_a_wrong_label_is_refused(labels, refused):
    fields = [f"labels: {labels}", HEALTH] if labels else []

    assert refused in refusal(compose(*fields), hosts=("hopin",))


def test_b2_two_services_labelled_with_one_host_are_refused():
    text = f"services: {{a: {service(routed=True)}, b: {service(routed=True)}}}"

    assert "host hopin needs exactly one service" in refusal(text, hosts=("hopin",))


def test_a_host_another_tunnel_serves_has_at_most_one_labelled_service():
    text = f"services: {{a: {service(routed=True)}, b: {service(routed=True)}}}"

    assert "host hopin needs at most one service" in refusal(
        text, hosts=("hopin",), served_elsewhere=frozenset({"hopin"})
    )


ALIASED = '{edge.name: hopin, edge.alias: talk, traefik.enable: "true"}'


def aliased(labels: str) -> str:
    return f"labels: {labels}, {HEALTH}"


@pytest.mark.parametrize(
    "fields",
    [
        aliased(ALIASED),
        "labels: ['edge.name=hopin', 'edge.alias=talk', 'traefik.enable=true']",
    ],
)
def test_an_alias_names_a_second_host_of_the_entry_in_either_label_form(fields):
    """#445 R1."""
    text = compose(fields, HEALTH if fields.startswith("labels: [") else "")

    assert app_contract.check(text, KEY, TAG, ("hopin", "talk"), served_elsewhere=frozenset()) == (
        "web",
    )


@pytest.mark.parametrize(
    ("labels", "refused"),
    [
        ('{edge.name: hopin, edge.alias: other, traefik.enable: "true"}', "edge.alias"),
        ('{edge.name: hopin, edge.alias: hopin, traefik.enable: "true"}', "edge.alias"),
        ('{edge.alias: talk, traefik.enable: "true"}', "edge.alias without edge.name"),
        ('{edge.name: hopin, edge.alias: "", traefik.enable: "true"}', "edge.alias"),
        ('{edge.name: hopin, edge.alias: Talk, traefik.enable: "true"}', "edge.alias"),
        ('{edge.name: hopin, edge.alias: "@", traefik.enable: "true"}', "edge.alias"),
        ('{edge.name: hopin, edge.alias: "*", traefik.enable: "true"}', "edge.alias"),
        ('{edge.name: Hopin, edge.alias: talk, traefik.enable: "true"}', "edge.alias"),
        (
            '{edge.name: hopin, edge.alias: "${H}", traefik.enable: "true"}',
            "interpolates a label ($) (edge.alias)",
        ),
    ],
)
def test_an_alias_that_breaks_a_rule_is_refused_naming_service_and_label(labels, refused):
    """#445 R1, R2: the refusal names the service and the label key."""
    message = refusal(compose(aliased(labels)), hosts=("hopin", "talk", "Talk", "@", "*", "Hopin"))

    assert "service web" in message
    assert refused in message


@pytest.mark.parametrize(
    "second_labels",
    [
        '{edge.name: talk, traefik.enable: "true"}',
        '{edge.name: other, edge.alias: talk, traefik.enable: "true"}',
    ],
)
def test_two_services_holding_one_host_by_name_or_alias_are_refused(second_labels):
    """#445 R2."""
    text = f"services: {{a: {service(aliased(ALIASED))}, b: {service(aliased(second_labels))}}}"

    assert "host talk needs exactly one service" in refusal(text, hosts=("hopin", "talk", "other"))


def test_a_host_no_service_holds_by_name_or_alias_is_refused():
    """#445 R2."""
    message = refusal(compose(aliased(ALIASED)), hosts=("hopin", "talk", "third"))

    assert "host third needs exactly one service" in message


def test_b2_a_label_as_list_entry_routes_like_one_as_map_entry():
    fields = ["labels: ['edge.name=hopin', 'traefik.enable=true']", HEALTH]

    assert app_contract.check(
        compose(*fields), KEY, TAG, ("hopin",), served_elsewhere=frozenset()
    ) == ("web",)


@pytest.mark.parametrize(
    ("text", "refused"),
    [
        (
            compose('labels: {edge.name: hopin, traefik.enable: "true"}'),
            "service web has no healthcheck (healthcheck)",
        ),
        (compose("restart: always"), "service web must restart unless-stopped (restart)"),
        (
            "services: {web: {image: x}}",
            "service web must restart unless-stopped (restart)",
        ),
        (compose('restart: "no"'), "service web is a one-shot (restart no)"),
        (compose("restart: no"), "service web is a one-shot (restart no)"),
        (compose('restart: "${R:-no}"'), "service web interpolates restart ($)"),
    ],
)
def test_b3_a_service_without_healthcheck_or_restart_unless_stopped_is_refused(text, refused):
    assert refused in refusal(text, hosts=("hopin",))


@pytest.mark.parametrize(
    ("health", "disabled"),
    [
        ("{test: [NONE]}", True),
        ("{test: NONE}", True),
        ("{disable: true}", True),
        ("{disable: yes}", True),
        ("{disable: on}", True),
        ("{disable: 'True'}", True),
        ("{test: [CMD, 'true'], disable: no}", False),
        ("{test: [CMD, 'true'], disable: off}", False),
        ("{test: [CMD, 'true'], disable: false}", False),
        ("{test: [CMD, 'true'], disable: 'false'}", False),
    ],
)
def test_a_healthcheck_is_disabled_as_compose_reads_the_boolean(health, disabled):
    labels = 'labels: {edge.name: hopin, traefik.enable: "true"}'
    text = compose(labels, f"healthcheck: {health}")

    if disabled:
        assert "service web has no healthcheck (healthcheck)" in refusal(text, hosts=("hopin",))
    else:
        assert app_contract.check(text, KEY, TAG, ("hopin",), served_elsewhere=frozenset()) == (
            "web",
        )


@pytest.mark.parametrize(
    ("health", "key"),
    [
        ('{test: ["${T}"]}', "test"),
        ("{test: [CMD, 'true'], disable: '${X}'}", "disable"),
    ],
)
def test_an_interpolated_healthcheck_key_of_a_labelled_service_is_refused(health, key):
    labels = 'labels: {edge.name: hopin, traefik.enable: "true"}'

    message = refusal(compose(labels, f"healthcheck: {health}"), hosts=("hopin",))

    assert f"service web interpolates the healthcheck {key} ($)" in message


@pytest.mark.parametrize(
    "fields",
    [
        "labels: ['${L}=other', 'edge.name=hopin', 'traefik.enable=true']",
        "labels: {'${L}': other, edge.name: hopin, traefik.enable: 'true'}",
        "labels: ['edge.name=${H}', 'traefik.enable=true']",
        "labels: {edge.name: hopin, traefik.enable: '${T:-true}'}",
    ],
)
def test_an_interpolated_label_key_or_deciding_value_is_refused_as_the_key(fields):
    message = refusal(compose(fields, HEALTH), hosts=("hopin",))

    assert "service web interpolates a label ($)" in message
    assert "other" not in message


@pytest.mark.parametrize(
    "mount",
    [
        "volumes: [{type: volume, source: '${W}', target: /data}]",
        "volumes: [{type: '${T}', source: d, target: /data}]",
        "volumes: [{type: bind, source: d, target: '${T}'}]",
        "volumes: [{type: tmpfs, target: /run, tmpfs: {size: '${S}'}}]",
        "volumes: ['d:${T}']",
        "volumes: ['${X}/data:/data']",
        "volumes: ['${W}:/data']",
        "volumes: ['./${X}:/data']",
        "volumes: ['/data${S:-foo}']",
        "volumes: ['./${ROOT:-data}:/data']",
        "volumes: ['~${X}:/data']",
        "volumes: ['./${X}:/data:ro']",
        "volumes: ['d:/data:${MODE:-ro}']",
        "tmpfs: ['${W}']",
    ],
)
def test_an_interpolated_volume_entry_is_refused_as_the_key(mount):
    assert "interpolates" in refusal(compose(mount))


@pytest.mark.parametrize(
    "mount",
    [
        "volumes: [{type: volume, source: d, target: /data, read_only: '${X:-true}'}]",
        "volumes: [{type: bind, source: '${X}', target: /data}]",
    ],
)
def test_an_interpolation_that_decides_no_rule_in_a_volume_entry_is_allowed(mount):
    assert (
        app_contract.check(compose(mount), KEY, TAG, (), served_elsewhere=frozenset())[0] == "web"
    )


def test_yes_is_no_boolean_for_traefik_enable_as_compose_reads_it():
    fields = ["labels: {edge.name: hopin, traefik.enable: yes}", HEALTH]

    assert "has edge.name without traefik.enable true" in refusal(
        compose(*fields), hosts=("hopin",)
    )


@pytest.mark.parametrize(
    "volume",
    [
        "'/data'",
        "{type: volume, target: /data}",
        "{type: bind, target: /data}",
        "':d'",
        "'::'",
        "':/'",
    ],
)
def test_b4_a_volume_entry_without_a_source_is_refused(volume):
    message = refusal(compose(f"volumes: [{volume}]"))

    assert "service web has a volume entry without a source (volumes)" in message


@pytest.mark.parametrize("volume", ["d:/data", "x:/data:ro", "d:", "C:\\data:/data", "é:/data"])
def test_a_short_volume_entry_that_starts_with_one_letter_is_refused_for_the_long_form(volume):
    message = refusal(compose(f"volumes: ['{volume}']"))

    assert "service web has a volume entry that starts with one letter (volumes)" in message
    assert "write it in the long form" in message


@pytest.mark.parametrize(
    "volume",
    [
        "dd:/data",
        "data:/data",
        "./x:/data:ro",
        ".:/data",
        "~:/data",
        "/:/data:ro",
        "1:/data",
        "_:/data",
    ],
)
def test_a_short_volume_entry_whose_first_section_is_no_letter_still_plans(volume):
    assert (
        app_contract.check(
            compose(f"volumes: ['{volume}']"), KEY, TAG, (), served_elsewhere=frozenset()
        )[0]
        == "web"
    )
    app_contract.check_image_volumes(
        compose(f"volumes: ['{volume}']"), KEY, TAG, {"web": ["/data"]}
    )


@pytest.mark.parametrize(
    "text",
    [
        compose(),
        compose("volumes: ['data:/data']"),
        compose("volumes: [{type: tmpfs, target: /run}]"),
        f"services: {{web: {service('depends_on: [db]')}, db: {service()}}}",
        compose(routed=True),
    ],
)
def test_a_compose_file_inside_the_contract_names_its_services(text):
    hosts = ("hopin",) if "edge.name" in text else ()

    assert app_contract.check(text, KEY, TAG, hosts, served_elsewhere=frozenset())[0] == "web"


@pytest.mark.parametrize(
    ("volumes", "declared", "uncovered"),
    [
        ("volumes: ['data:/data']", ["/data"], None),
        ("volumes: ['./data:/data/']", ["/data"], None),
        ("volumes: [{type: volume, source: d, target: /data}]", ["/data"], None),
        ("tmpfs: /data", ["/data"], None),
        ("volumes: ['data:/other']", ["/data"], "/data"),
        ("volumes: ['data:/data/sub']", ["/data"], "/data"),
        ("volumes: [{type: bind, source: '${X}', target: /data}]", ["/data"], None),
        ("volumes: [{type: volume, source: d, target: /data}]", ["/data", "/x"], "/x"),
    ],
)
def test_b5_an_image_volume_is_covered_only_by_a_mount_of_the_same_path(
    volumes, declared, uncovered
):
    text = compose(volumes)

    if uncovered is None:
        app_contract.check_image_volumes(text, KEY, TAG, {"web": declared})
        return
    with pytest.raises(app_contract.ContractError) as refused:
        app_contract.check_image_volumes(text, KEY, TAG, {"web": declared})
    assert str(refused.value) == (
        f"services.hopin: image of service web at {TAG} declares a volume that no named volume "
        "of the service covers (volumes); give it a named volume"
    )
    assert uncovered not in str(refused.value)

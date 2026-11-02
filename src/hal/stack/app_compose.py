"""Every `docker compose` call of an app, whose failure line carries no word of Compose's output.

An app's compose project is its key. Compose echoes interpolated values in its errors, so no
output of a build, pull, create, start or ps is ever read into a message: a failure names the
call, the app, the tag and the exit code and says the output is withheld; the operator reads it
by running the step himself in `~/srv/<key>` (E7). What is observed is the project's containers,
asked file-free (`-p <key>` alone), so it holds whatever compose.yaml the checkout carries; so are
`stop` and `rm -f`, with which an app is switched off.

The start never builds or pulls: `build` and `pull` come first, then `create --no-build --pull
never` makes the containers from what was built, and `start` starts them.
"""

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from hal.stack import compose, deploy_checkout

BUILD_SECONDS = 1800
PULL_SECONDS = 600
_HEALTHY = "healthy"
_RUNNING = "running"


@dataclass(frozen=True)
class AppContainer:
    """One container of the app's project as `ps` lists it; `health` is empty without a check."""

    name: str
    identifier: str
    service: str
    state: str
    health: str

    @property
    def settled(self) -> bool:
        """Running, and healthy as well where Docker reports a health state (a healthcheck)."""
        return self.state == _RUNNING and self.health in ("", _HEALTHY)

    def describe(self) -> str:
        shown = f"{self.service} {self.state}"
        return f"{shown} ({self.health})" if self.health else shown


@dataclass(frozen=True)
class AppCompose:
    key: str
    directory: Path
    run: compose.Runner = compose.run_docker

    def containers(self) -> list[AppContainer]:
        """Every container of project `<key>`, stopped ones too."""
        output = self._call("ps", ["--all", "--format", "json"], compose.READ_SECONDS)
        try:
            return [_container(entry) for entry in compose.ps_entries(output)]
        except KeyError, TypeError:
            raise compose.ComposeError(
                f"`docker compose ps` of {self.key} answered no list of containers"
            ) from None

    def build(self, tag: str) -> None:
        self._call("build", [], BUILD_SECONDS, tag)

    def pull(self, tag: str) -> None:
        """The images of the services that are not built here; nothing else is fetched."""
        self._call("pull", ["--ignore-buildable"], PULL_SECONDS, tag)

    def image_volumes(self, services: Sequence[str], tag: str) -> dict[str, list[str]]:
        """The paths that the image of each service declares as a VOLUME. The images are those
        that `config` resolves per service, as built or pulled by now; its output is parsed here
        and never printed."""
        images = self._service_images(tag)
        declared = {}
        for service in services:
            if service not in images:
                raise compose.ComposeError(
                    f"`docker compose config` of {self.key} at {tag} names no image of a service"
                )
            declared[service] = self._declared_volumes(images[service], tag)
        return declared

    def create(self, tag: str) -> None:
        """New containers for the services whose definition changed, none started and nothing
        built or pulled; a container of a service the file no longer names is removed."""
        arguments = ["--no-build", "--pull", "never", "--remove-orphans"]
        self._call("create", arguments, compose.CHANGE_SECONDS, tag)

    def start(self, tag: str) -> None:
        self._call("start", [], compose.CHANGE_SECONDS, tag)

    def start_stopped(self) -> None:
        """Starts the stopped containers of project `<key>`, file-free, and makes none."""
        self._call("start", [], compose.CHANGE_SECONDS)

    def stop(self) -> None:
        """Stops every container of project `<key>`; file-free, so it holds whatever the
        checkout carries."""
        self._call("stop", [], compose.CHANGE_SECONDS)

    def remove(self) -> None:
        """Removes every stopped container of project `<key>`, file-free. No `-v`: the volumes
        stay, named and anonymous alike."""
        self._call("rm", ["-f"], compose.CHANGE_SECONDS)

    def remove_by_identifier(self, identifiers: Sequence[str]) -> None:
        """Removes the given containers of project `<key>`, which `stop` and `rm -f` leave behind
        (those of `compose run`). Only identifiers that `ps` listed; no `-v`."""
        result = self.run(["docker", "rm", "-f", *identifiers], compose.CHANGE_SECONDS)
        if result.returncode != 0:
            raise compose.ComposeError(
                f"`docker rm` of {self.key} exited {result.returncode}; "
                "its output is withheld, run the step to read it"
            )

    def _service_images(self, tag: str) -> dict[str, str]:
        output = self._call("config", ["--format", "json"], compose.READ_SECONDS, tag)
        try:
            services = json.loads(output)["services"]
            # Compose leaves `image` out of a service that is built here and names it
            # `<project>-<service>`.
            return {
                name: str(one.get("image") or f"{self.key}-{name}")
                for name, one in services.items()
            }
        except ValueError, KeyError, TypeError, AttributeError:
            raise compose.ComposeError(
                f"`docker compose config` of {self.key} at {tag} answered no image per service"
            ) from None

    def _declared_volumes(self, image: str, tag: str) -> list[str]:
        command = ["docker", "image", "inspect", "--format", "{{json .Config.Volumes}}", image]
        result = self.run(command, compose.READ_SECONDS)
        if result.returncode != 0:
            raise compose.ComposeError(
                f"`docker image inspect` for {self.key} at {tag} exited {result.returncode}; "
                "its output is withheld, run the step in the app's checkout to read it"
            )
        try:
            volumes = json.loads(result.stdout)
            return sorted(volumes) if isinstance(volumes, dict) else []
        except ValueError:
            raise compose.ComposeError(
                f"`docker image inspect` for {self.key} at {tag} answered no JSON"
            ) from None

    def _call(self, verb: str, arguments: list[str], timeout: int, tag: str | None = None) -> str:
        """`tag` set: the call is bound to the checkout's compose.yaml, which is that tag's."""
        command = ["docker", "compose", "-p", self.key]
        if tag is not None:
            file = self.directory / deploy_checkout.COMPOSE_FILE
            command += ["--project-directory", str(self.directory), "--file", str(file)]
        result = self.run([*command, verb, *arguments], timeout)
        if result.returncode != 0:
            at = f" at {tag}" if tag is not None else ""
            raise compose.ComposeError(
                f"`docker compose {verb}` of {self.key}{at} exited {result.returncode}; "
                "its output is withheld, run the step in the app's checkout to read it"
            )
        return result.stdout


def _container(entry: dict) -> AppContainer:
    """Raises KeyError or TypeError for an entry that is no container."""
    return AppContainer(
        str(entry["Name"]),
        str(entry["ID"]),
        str(entry["Service"]),
        str(entry["State"]),
        str(entry.get("Health", "")),
    )

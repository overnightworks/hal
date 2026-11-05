"""Loading a script of the repository as a module, with `sys.path` and the repository's own
modules as they were before. A probe script puts its directories on `sys.path` when it loads and
imports its siblings by bare name; none of that outlives the loading."""

import importlib.util
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIRECTORIES = (ROOT / "probe", ROOT / "agent-service")


def _lies_under_script_directories(module: ModuleType) -> bool:
    file = getattr(module, "__file__", None)
    return file is not None and any(
        Path(file).resolve().is_relative_to(directory) for directory in SCRIPT_DIRECTORIES
    )


@contextmanager
def importing_from(*directories: Path) -> Iterator[None]:
    """`directories` first on `sys.path` for the length of the `with`; afterwards `sys.path` is as
    it was, and the modules of `probe/` and `agent-service/` imported meanwhile are forgotten, so
    the next import of one reads it afresh. Other modules (a library first imported here) stay."""
    path_before = list(sys.path)
    modules_before = set(sys.modules)
    sys.path[:0] = [str(directory) for directory in directories]
    try:
        yield
    finally:
        sys.path[:] = path_before
        for name in set(sys.modules) - modules_before:
            if _lies_under_script_directories(sys.modules[name]):
                del sys.modules[name]


def loaded_script(name: str, path: Path, *directories: Path) -> Iterator[ModuleType]:
    """The module of the script at `path` (with or without a `.py` suffix) under `name`, with
    `directories` first on `sys.path` while it loads, until the iterator is resumed."""
    with importing_from(*directories):
        loader = SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # its dataclasses resolve their annotations through it
        try:
            loader.exec_module(module)
            yield module
        finally:
            del sys.modules[name]


script_module = contextmanager(loaded_script)

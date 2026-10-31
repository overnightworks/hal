"""A secret pasted into the terminal without echo, read whole: a token printed across line breaks
arrives as several lines, so the paste runs up to the first empty or whitespace-only line, and
its stripped lines are joined into one token. Nothing is judged before that empty line, and every
way out after the prompt first drains what is still queued, so no part of a paste is left in the
input for the next reader. Only `/dev/tty` is read; there is no echoed fallback."""

import os
import termios

LINE_LIMIT = 4095
"""Linux's n_tty keeps at most 4095 bytes of a canonical line and silently drops the rest, so a
line this long may have been cut."""
END_HINT = "then an empty line"
"""What both prompts tell the person: the paste ends at an empty line."""
_READ_SIZE = LINE_LIMIT + 1  # one canonical line with its newline


class PasteRefused(Exception):
    """The paste cannot be one token; its sentence holds no part of the paste and no length."""


class TerminalCannotHide(Exception):
    """The terminal cannot hide the paste; nothing was shown as a prompt and nothing was read."""


class TerminalNotRestored(Exception):
    """The paste was read, but the terminal could not be set back; the paste was discarded."""

    def __init__(self) -> None:
        super().__init__(
            "the paste was read but the terminal could not be set back, so typing may stay "
            "hidden; run `stty sane`"
        )


def is_visible_ascii(value: str) -> bool:
    """Every token the providers issue is visible ASCII (`!`..`~`)."""
    return all("!" <= character <= "~" for character in value)


def read_hidden_paste(prompt: str) -> str:
    """The paste after `prompt`, its lines stripped and joined; empty when the first line is.
    Ctrl-C raises KeyboardInterrupt and Ctrl-D EOFError, after the terminal is set back."""
    try:
        terminal = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        raise TerminalCannotHide("there is no terminal to read the paste from") from None
    try:
        lines = _hidden_lines(terminal, prompt)
        paste = _joined(lines)
        if len(lines) > 1:
            indent = prompt[: len(prompt) - len(prompt.lstrip())]
            os.write(terminal, f"{indent}joined {len(lines)} pasted lines into one\n".encode())
        return paste
    finally:
        os.close(terminal)


def _hidden_lines(terminal: int, prompt: str) -> list[bytes]:
    try:
        settings = termios.tcgetattr(terminal)
        hidden = [*settings[:3], settings[3] & ~termios.ECHO, *settings[4:]]
        termios.tcsetattr(terminal, termios.TCSAFLUSH, hidden)
    except termios.error:
        raise TerminalCannotHide("the terminal cannot turn its echo off") from None
    try:
        os.write(terminal, prompt.encode())
        lines = _lines_up_to_the_empty_one(terminal)
    finally:
        rest = _drained_and_restored(terminal, settings)
    os.write(terminal, b"\n")
    if rest:
        raise PasteRefused("text came after the empty line that ends the paste; nothing was kept")
    return lines


def _lines_up_to_the_empty_one(terminal: int) -> list[bytes]:
    lines: list[bytes] = []
    while (line := _line(terminal)).strip():
        lines.append(line)
    return lines


def _line(terminal: int) -> bytes:
    line = b""
    while not line.endswith(b"\n"):
        chunk = os.read(terminal, _READ_SIZE)
        if not chunk:
            raise EOFError
        line += chunk
    return line.removesuffix(b"\n")


def _drained_and_restored(terminal: int, settings: list) -> bytes:
    """What is still queued, read without waiting; then the settings back with TCSANOW, so input
    that arrives later stays for the next reader instead of being discarded unseen."""
    draining = [*settings[:3], settings[3] & ~(termios.ECHO | termios.ICANON), *settings[4:6]]
    characters = list(settings[6])
    characters[termios.VMIN] = 0
    characters[termios.VTIME] = 0
    try:
        try:
            termios.tcsetattr(terminal, termios.TCSANOW, [*draining, characters])
            rest = b""
            while chunk := os.read(terminal, _READ_SIZE):
                rest += chunk
        finally:
            termios.tcsetattr(terminal, termios.TCSANOW, settings)
    except (termios.error, OSError):
        raise TerminalNotRestored from None
    return rest


def _joined(lines: list[bytes]) -> str:
    if any(len(line) >= LINE_LIMIT for line in lines):
        raise PasteRefused("a pasted line is too long for the terminal and may have been cut")
    texts = [_decoded(line) for line in lines]
    parts = [text.strip() for text in texts if text is not None]
    if len(parts) < len(texts):
        raise PasteRefused("the paste is not UTF-8 text")
    if len(parts) > 1 and not all(is_visible_ascii(part) for part in parts):
        raise PasteRefused(f"the {len(parts)} pasted lines are not one token")
    return "".join(parts)


def _decoded(line: bytes) -> str | None:
    """The line as UTF-8, else None: a refusal raised here would keep the bytes in its chain."""
    try:
        return line.decode()
    except UnicodeDecodeError:
        return None

"""Professional terminal output helpers for the HexSOC Agent."""

from __future__ import annotations

from typing import Any

try:
    from colorama import Fore, Style, init
except ImportError:  # pragma: no cover - plain output fallback.
    class _EmptyColor:
        BLACK = ""
        BLUE = ""
        CYAN = ""
        GREEN = ""
        MAGENTA = ""
        RED = ""
        RESET_ALL = ""
        WHITE = ""
        YELLOW = ""
        BRIGHT = ""
        DIM = ""
        NORMAL = ""

    Fore = _EmptyColor()
    Style = _EmptyColor()

    def init(*args: Any, **kwargs: Any) -> None:
        return None


init(autoreset=True)

SEPARATOR = "=" * 48


def colorize(value: Any, color: str = "", bright: bool = False) -> str:
    """Return colored text when ANSI is supported, plain text otherwise."""
    prefix = f"{Style.BRIGHT if bright else ''}{color}"
    return f"{prefix}{value}{Style.RESET_ALL}"


def status_color(status: str) -> str:
    """Return a color for common status labels."""
    normalized = status.upper()
    if normalized in {"SUCCESS"}:
        return Fore.GREEN
    if normalized in {"FAILED", "CANCELLED", "ERROR"}:
        return Fore.RED
    if normalized in {"WARNING", "PENDING"}:
        return Fore.YELLOW
    return Fore.CYAN


def print_block(title: str, fields: list[tuple[str, Any]], status: str = "INFO", message: str | None = None) -> None:
    """Print a colored, aligned CLI status block."""
    color = status_color(status)
    print(colorize(SEPARATOR, color, bright=True))
    print(colorize(title, color, bright=True))
    print(colorize(SEPARATOR, color, bright=True))
    for label, value in fields:
        width = max(20, len(label))
        if label.lower() == "status":
            value = colorize(value, status_color(str(value)), bright=True)
        print(f"{label:<{width}}: {value}")
    if message:
        print()
        print(colorize(message, color, bright=True))
    print(colorize(SEPARATOR, color, bright=True))


def print_success_block(title: str, fields: list[tuple[str, Any]], message: str | None = None) -> None:
    """Print a green success block."""
    print_block(title, fields, status="SUCCESS", message=message)


def print_error_block(title: str, fields: list[tuple[str, Any]], message: str | None = None) -> None:
    """Print a red failed/cancelled block."""
    print_block(title, fields, status="FAILED", message=message)


def print_warning_block(title: str, fields: list[tuple[str, Any]], message: str | None = None) -> None:
    """Print a yellow warning block."""
    print_block(title, fields, status="WARNING", message=message)


def print_info_block(title: str, fields: list[tuple[str, Any]], message: str | None = None) -> None:
    """Print a cyan informational block."""
    print_block(title, fields, status="INFO", message=message)

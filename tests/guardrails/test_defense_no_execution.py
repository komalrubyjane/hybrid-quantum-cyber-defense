"""Safety boundary: hqc.defense is advisory only and must contain no execution paths.

Static AST scan of every module under backend/hqc/defense. Fails on imports of
process / shell / network / remote-execution / system-control modules and on calls
such as os.system, os.kill, eval or exec. The scanner is itself tested below so the
guardrail cannot pass vacuously.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

import hqc.defense

pytestmark = pytest.mark.guardrail

DEFENSE_DIR = Path(hqc.defense.__file__).parent

FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {
        # process / shell execution
        "subprocess",
        "pty",
        "pexpect",
        "sh",
        "plumbum",
        "multiprocessing",
        "ctypes",
        "cffi",
        # raw network / HTTP clients (no outbound calls to firewalls, EDR, cloud APIs)
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "websockets",
        "ftplib",
        "telnetlib",
        "smtplib",
        # remote execution / device configuration
        "paramiko",
        "fabric",
        "asyncssh",
        "netmiko",
        "napalm",
        "ncclient",
        "pysnmp",
        # firewall / routing / network configuration
        "iptc",
        "nftables",
        "pyroute2",
        "scapy",
        "netfilterqueue",
        # account / host / cloud control
        "pwd",
        "grp",
        "psutil",
        "docker",
        "kubernetes",
        "boto3",
        "botocore",
        "azure",
        "google",
        "winreg",
        "win32api",
        "win32security",
        "ldap3",
        # dynamic import / code loading that could hide the above
        "importlib",
        "runpy",
    }
)

# os.<attr> / shutil.<attr> / signal.<attr> calls that act on the real system.
FORBIDDEN_ATTRIBUTE_CALLS: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
        "os.kill",
        "os.killpg",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.removedirs",
        "os.chmod",
        "os.chown",
        "os.setuid",
        "os.setgid",
        "os.fork",
        "os.startfile",
        "shutil.rmtree",
        "shutil.move",
        "shutil.chown",
        "signal.pthread_kill",
    }
)
FORBIDDEN_PREFIX_CALLS: tuple[str, ...] = ("os.exec", "os.spawn", "os.posix_spawn")
FORBIDDEN_BUILTINS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})


@dataclass(frozen=True)
class Violation:
    file: str
    line: int
    detail: str


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def scan_source(source: str, filename: str = "<string>") -> list[Violation]:
    """Return guardrail violations found in Python source."""
    tree = ast.parse(source, filename=filename)
    found: list[Violation] = []
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules = [node.module]
        for mod in modules:
            if mod.split(".")[0] in FORBIDDEN_MODULES:
                found.append(Violation(filename, node.lineno, f"forbidden import '{mod}'"))
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name is None:
                continue
            if (
                name in FORBIDDEN_ATTRIBUTE_CALLS
                or name in FORBIDDEN_BUILTINS
                or name.startswith(FORBIDDEN_PREFIX_CALLS)
            ):
                found.append(Violation(filename, node.lineno, f"forbidden call '{name}'"))
    return found


def _defense_files() -> list[Path]:
    return sorted(DEFENSE_DIR.rglob("*.py"))


def test_defense_package_exists() -> None:
    assert _defense_files(), "hqc.defense should contain at least __init__.py"


@pytest.mark.parametrize("path", _defense_files(), ids=lambda p: p.name)
def test_defense_module_has_no_execution_paths(path: Path) -> None:
    violations = scan_source(path.read_text(encoding="utf-8"), str(path))
    assert not violations, "\n".join(f"{v.file}:{v.line}: {v.detail}" for v in violations)


def test_defense_package_has_no_non_python_executables() -> None:
    suspicious = [
        p
        for p in DEFENSE_DIR.rglob("*")
        if p.is_file() and p.suffix in {".sh", ".bash", ".ps1", ".bat", ".cmd", ".exe"}
    ]
    assert not suspicious


# --- scanner self-tests: the guardrail must actually catch violations -----------


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess",
        "from subprocess import run",
        "import os\nos.system('x')",
        "import os\nos.kill(1, 9)",
        "import os\nos.execv('a', [])",
        "import paramiko",
        "from netmiko import ConnectHandler",
        "import socket",
        "import requests",
        "import urllib.request",
        "import iptc",
        "import shutil\nshutil.rmtree('/x')",
        "eval('1')",
        "exec('x=1')",
        "__import__('subprocess')",
        "import importlib",
    ],
)
def test_scanner_detects_violation(snippet: str) -> None:
    assert scan_source(snippet), f"scanner missed: {snippet!r}"


@pytest.mark.parametrize(
    "snippet",
    [
        "from hqc.common.schemas import DefenseRecommendation",
        "import math\nx = math.sqrt(2)",
        "from pathlib import Path\np = Path('x')",
        "def recommend(x):\n    return [x]",
    ],
)
def test_scanner_allows_safe_code(snippet: str) -> None:
    assert scan_source(snippet) == []

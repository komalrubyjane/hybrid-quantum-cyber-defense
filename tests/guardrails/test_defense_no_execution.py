"""Safety boundary: hqc.defense is advisory only and must contain no execution paths.

Static AST scan of every module under backend/hqc/defense. Fails on imports of
process / shell / network / remote-execution / system-control modules and on calls
such as os.system, os.kill, eval or exec. The scanner is itself tested below so the
guardrail cannot pass vacuously.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

import hqc.defense
import hqc.risk

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
        # Milestone 7 expansion: process control, async subprocess, files and persistence.
        # The defense package only builds typed recommendations in memory.
        "os",
        "shutil",
        "signal",
        "sys",
        "asyncio",
        "threading",
        "concurrent",
        "pickle",
        "marshal",
        "joblib",
        "shelve",
        "sqlite3",
        "tempfile",
        "glob",
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
FORBIDDEN_BUILTINS: frozenset[str] = frozenset(
    {"eval", "exec", "compile", "__import__", "open", "breakpoint"}
)
# Milestone 7: string literals that look like firewall / account / process / host commands.
FORBIDDEN_COMMAND_PATTERN = re.compile(
    r"\b(iptables|ip6tables|nft|ufw|firewall-cmd|netsh|pfctl|usermod|userdel|useradd|chpasswd|"
    r"passwd|Disable-ADAccount|Set-ADUser|Stop-Process|taskkill|pkill|killall|kill -9|kubectl|"
    r"systemctl|shutdown|reboot|ip route|route add|sudo|ssh |scp |rm -rf|aws |gcloud |az )",
    re.IGNORECASE,
)


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
    docstrings = {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and n.body
        and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
        and isinstance(n.body[0].value.value, str)
    }
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules = [node.module]
        for mod in modules:
            if mod.split(".")[0] in FORBIDDEN_MODULES:
                found.append(Violation(filename, node.lineno, f"forbidden import '{mod}'"))
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings  # prose describing the prohibition is allowed
        ):
            match = FORBIDDEN_COMMAND_PATTERN.search(node.value)
            if match:
                found.append(
                    Violation(filename, node.lineno, f"command-like literal {match.group(0)!r}")
                )
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


RISK_DIR = Path(hqc.risk.__file__).parent


def _risk_files() -> list[Path]:
    return sorted(RISK_DIR.rglob("*.py"))


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
        "import os",
        "import asyncio",
        "from concurrent.futures import ProcessPoolExecutor",
        "import pickle",
        "open('/etc/hosts', 'w')",
        "x = 'iptables -A INPUT -s 1.2.3.4 -j DROP'",
        "x = 'usermod -L alice'",
        "x = 'Disable-ADAccount -Identity bob'",
        "x = 'taskkill /PID 4 /F'",
        "x = 'kubectl delete pod web'",
        "x = 'sudo shutdown now'",
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
        "x = 'consider isolating the resource pending human approval'",
        "x = 'consider resetting or disabling the account pending human approval'",
        '"""Never runs iptables or SSH."""\ndef f():\n    """No sudo here."""',
    ],
)
def test_scanner_allows_safe_code(snippet: str) -> None:
    assert scan_source(snippet) == []


# --- Milestone 7 expansion -------------------------------------------------------------------


@pytest.mark.parametrize("path", _risk_files(), ids=lambda p: p.name)
def test_risk_module_has_no_execution_paths(path: Path) -> None:
    violations = scan_source(path.read_text(encoding="utf-8"), str(path))
    assert not violations, "\n".join(f"{v.file}:{v.line}: {v.detail}" for v in violations)


def test_defense_package_contains_the_recommender() -> None:
    names = {p.name for p in _defense_files()}
    assert "recommender.py" in names  # the guardrail must actually cover the M7 code


def test_defense_recommendations_always_require_human_approval() -> None:
    from hqc.common.schemas.defense import DefenseRecommendation

    field = DefenseRecommendation.model_fields["requires_human_approval"]
    assert field.default is True
    assert str(field.annotation) in {"typing.Literal[True]", "Literal[True]"}


def test_defense_service_exposes_no_execution_api() -> None:
    from hqc.defense import recommender

    public = [n for n in dir(recommender.DefenseRecommendationService) if not n.startswith("_")]
    assert set(public) == {"planned_actions", "recommend"}

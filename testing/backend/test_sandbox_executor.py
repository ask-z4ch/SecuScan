import asyncio
import platform
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.secuscan.models import SandboxConfig, SandboxViolation
from backend.secuscan.sandbox_executor import (
    sandbox_execute,
    resolve_sandbox_config,
    GRACE_AFTER_SIGTERM,
)


@pytest.mark.asyncio
async def test_sandbox_execute_normal_completion():
    cfg = SandboxConfig(timeout_seconds=30)
    output, exit_code, violation = await sandbox_execute(
        [sys.executable, "-c", "print('hello world')"],
        "test-normal",
        cfg,
    )
    assert "hello world" in output
    assert exit_code == 0
    assert violation is None


@pytest.mark.asyncio
async def test_sandbox_execute_timeout_triggers_violation():
    cfg = SandboxConfig(timeout_seconds=1, max_memory_mb=4096)
    output, exit_code, violation = await sandbox_execute(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        "test-timeout",
        cfg,
    )
    assert violation is not None
    assert violation.reason == "timeout"
    assert "timeout" in violation.detail.lower()
    assert "1s" in violation.threshold
    assert exit_code != 0


@pytest.mark.asyncio
async def test_sandbox_execute_output_cap_triggers_violation():
    cfg = SandboxConfig(max_output_bytes=100, timeout_seconds=30)
    output, exit_code, violation = await sandbox_execute(
        [sys.executable, "-c", "print('x' * 5000)"],
        "test-output-cap",
        cfg,
    )
    assert violation is not None
    assert violation.reason == "output_limit"
    assert len(output.encode("utf-8")) < 200
    assert exit_code != 0


@pytest.mark.asyncio
async def test_sandbox_execute_output_truncated_not_silent():
    cfg = SandboxConfig(max_output_bytes=50, timeout_seconds=30)
    output, exit_code, violation = await sandbox_execute(
        [sys.executable, "-c", "print('hello world ' * 50)"],
        "test-truncation",
        cfg,
    )
    assert violation is not None
    assert violation.reason == "output_limit"
    assert len(output) < 100
    assert "hello" in output


@pytest.mark.asyncio
async def test_sandbox_execute_cancelled_error_propagates():
    cfg = SandboxConfig(timeout_seconds=30)
    task = asyncio.create_task(
        sandbox_execute(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            "test-cancel",
            cfg,
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_resolve_sandbox_config_global_defaults(monkeypatch):
    monkeypatch.setattr(
        "backend.secuscan.sandbox_executor.settings.sandbox_timeout_seconds",
        42,
    )
    monkeypatch.setattr(
        "backend.secuscan.sandbox_executor.settings.sandbox_max_memory_mb",
        256,
    )

    resolved = resolve_sandbox_config(None)
    assert resolved.timeout_seconds == 42
    assert resolved.max_memory_mb == 256
    assert resolved.max_output_bytes == 5_242_880


@pytest.mark.asyncio
async def test_resolve_sandbox_config_plugin_overrides():
    resolved = resolve_sandbox_config(
        SandboxConfig(timeout_seconds=999, max_memory_mb=2048)
    )
    assert resolved.timeout_seconds == 999
    assert resolved.max_memory_mb == 2048
    assert resolved.max_output_bytes == 5_242_880


@pytest.mark.asyncio
async def test_resolve_sandbox_config_partial_override():
    resolved = resolve_sandbox_config(
        SandboxConfig(timeout_seconds=600)
    )
    assert resolved.timeout_seconds == 600
    assert resolved.max_memory_mb == 512
    assert resolved.allow_network is True


def test_sandbox_violation_model():
    v = SandboxViolation(
        reason="timeout",
        detail="Execution exceeded 120s timeout",
        threshold="120s",
    )
    assert v.reason == "timeout"
    assert "120s" in v.threshold
    d = v.model_dump()
    assert d["reason"] == "timeout"


@pytest.mark.asyncio
async def test_sandbox_execute_broadcast_callback():
    received = []

    async def cb(chunk: str):
        received.append(chunk)

    cfg = SandboxConfig(timeout_seconds=30)
    await sandbox_execute(
        [sys.executable, "-c", "print('broadcast me')"],
        "test-broadcast",
        cfg,
        broadcast_callback=cb,
    )
    combined = "".join(received)
    assert "broadcast me" in combined


@pytest.mark.asyncio
async def test_sandbox_execute_platform_guard_does_not_crash():
    cfg = SandboxConfig(timeout_seconds=10, max_memory_mb=128)
    output, exit_code, violation = await sandbox_execute(
        [sys.executable, "-c", "print('ok')"],
        "test-platform-guard",
        cfg,
    )
    assert exit_code == 0
    assert violation is None
    assert "ok" in output

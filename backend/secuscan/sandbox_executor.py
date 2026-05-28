import asyncio
import logging
import platform
from asyncio import subprocess
from typing import Callable, Optional, Tuple

from .models import SandboxConfig, SandboxViolation
from .config import settings

logger = logging.getLogger(__name__)

_LINUX = platform.system() == "Linux"

GRACE_AFTER_SIGTERM = 3


def resolve_sandbox_config(plugin_sandbox: Optional[SandboxConfig] = None) -> SandboxConfig:
    """Merge global settings with optional per-plugin sandbox overrides."""
    base = SandboxConfig(
        timeout_seconds=settings.sandbox_timeout_seconds,
        max_memory_mb=settings.sandbox_max_memory_mb,
        max_output_bytes=settings.sandbox_max_output_bytes,
        allow_network=settings.sandbox_allow_network,
    )
    if not plugin_sandbox:
        return base
    overrides = plugin_sandbox.model_dump(exclude_none=True)
    return base.model_copy(update=overrides)


def _apply_rlimit(config: SandboxConfig):
    mem_bytes = config.max_memory_mb * 1024 * 1024
    cpu_seconds = config.timeout_seconds
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
    except (ImportError, ResourceWarning):
        pass


async def sandbox_execute(
    command: list,
    task_id: str,
    config: SandboxConfig,
    broadcast_callback: Optional[Callable] = None,
) -> Tuple[str, int, Optional[SandboxViolation]]:
    """
    Execute a subprocess under sandbox resource constraints.

    Returns (output, exit_code, violation). ``violation`` is ``None`` when
    the process completed normally within all configured limits.
    """
    extra_kw = {}
    if _LINUX:
        extra_kw["preexec_fn"] = lambda: _apply_rlimit(config)

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **extra_kw,
    )

    output_bytes = bytearray()
    violation: Optional[SandboxViolation] = None

    async def _read_stdout():
        nonlocal violation, output_bytes
        stdout = process.stdout
        if stdout is None:
            return
        cap = config.max_output_bytes
        while not stdout.at_eof():
            chunk = await stdout.read(4096)
            if not chunk:
                break
            remaining = cap - len(output_bytes)
            if remaining <= 0:
                if violation is None:
                    violation = SandboxViolation(
                        reason="output_limit",
                        detail=f"Output exceeded {cap} bytes and was truncated",
                        threshold=f"{cap} bytes",
                    )
                    logger.warning("Task %s output cap (%d bytes) reached", task_id, cap)
                    process.kill()
                    await process.wait()
                continue
            if len(chunk) > remaining:
                output_bytes.extend(chunk[:remaining])
                if violation is None:
                    violation = SandboxViolation(
                        reason="output_limit",
                        detail=f"Output exceeded {cap} bytes and was truncated",
                        threshold=f"{cap} bytes",
                    )
                    logger.warning("Task %s output cap (%d bytes) reached", task_id, cap)
                    process.kill()
                    await process.wait()
            else:
                output_bytes.extend(chunk)
            if broadcast_callback:
                decoded = chunk.decode("utf-8", errors="replace")
                await broadcast_callback(decoded)

    try:
        await asyncio.wait_for(_read_stdout(), timeout=config.timeout_seconds)
        await process.wait()
    except asyncio.TimeoutError:
        if violation is None:
            violation = SandboxViolation(
                reason="timeout",
                detail=f"Execution exceeded {config.timeout_seconds}s timeout",
                threshold=f"{config.timeout_seconds}s",
            )
            logger.warning("Task %s timed out after %ds", task_id, config.timeout_seconds)
        await _escalate_terminate(process, task_id)
    except asyncio.CancelledError:
        logger.warning("Task %s cancelled, killing subprocess", task_id)
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise

    output = output_bytes.decode("utf-8", errors="replace")
    exit_code = process.returncode if process.returncode is not None else -1
    return output, exit_code, violation


async def _escalate_terminate(process, task_id: str):
    try:
        process.terminate()
    except ProcessLookupError:
        return
    await asyncio.sleep(GRACE_AFTER_SIGTERM)
    if process.returncode is not None:
        return
    logger.warning("Task %s did not respond to SIGTERM within %ds, sending SIGKILL", task_id, GRACE_AFTER_SIGTERM)
    try:
        process.kill()
    except ProcessLookupError:
        pass

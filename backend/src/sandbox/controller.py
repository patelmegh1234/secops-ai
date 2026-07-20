"""
Docker Sandbox Controller.
Runs pytest inside an isolated, network-disabled Docker container
to verify that the generated patch doesn't break existing tests.

Security guarantees:
  - network_disabled=True  (zero data exfiltration)
  - mem_limit="512m"       (prevents memory bombs)
  - cpu_quota=50000        (50% of one core)
  - Hard timeout = 30s     (container is killed after this)
  - Auto-remove on exit    (no container leaks)
"""

import asyncio
import io
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass

import docker
import docker.errors
from docker.models.containers import Container

from src.core.config import get_settings
from src.core.logging import get_logger
from src.sandbox.result_parser import parse_pytest_output

settings = get_settings()
logger = get_logger(__name__)


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    tests_passed: int
    tests_failed: int
    tests_errored: int
    duration_ms: int
    timed_out: bool
    container_id: str | None

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def _get_docker_client() -> docker.DockerClient:
    """Connect to Docker daemon (local socket or DOCKER_HOST env var)."""
    try:
        client = docker.from_env(timeout=10)
        client.ping()
        return client
    except docker.errors.DockerException as e:
        logger.error("docker_connection_failed", error=str(e))
        raise RuntimeError(
            "Cannot connect to Docker daemon. "
            "Ensure Docker is running and the socket is accessible."
        ) from e


async def run_sandbox(
    repo_owner: str,
    repo_name: str,
    branch: str,
    file_path: str,
    patched_code: str,
) -> SandboxResult:
    """
    Clone repository, apply patch, run pytest in isolated container.

    Args:
        repo_owner: GitHub repository owner.
        repo_name: GitHub repository name.
        branch: Branch to checkout.
        file_path: Relative path of the file to patch within the repo.
        patched_code: The AI-generated replacement file content.

    Returns:
        SandboxResult with test outcomes and container metadata.
    """
    start_ms = int(time.time() * 1000)
    workdir = tempfile.mkdtemp(prefix="secops_sandbox_")
    container: Container | None = None

    try:
        # ── Step 1: Clone repository ───────────────────────────────────────
        logger.info(
            "sandbox_clone_start",
            repo=f"{repo_owner}/{repo_name}",
            branch=branch,
        )

        clone_result = await asyncio.create_subprocess_exec(
            "git", "clone",
            "--depth", "1",
            "--branch", branch,
            f"https://x-access-token:{settings.github_token}@github.com/{repo_owner}/{repo_name}.git",
            workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr_bytes = await asyncio.wait_for(clone_result.communicate(), timeout=60.0)

        if clone_result.returncode != 0:
            err = stderr_bytes.decode()
            logger.error("sandbox_clone_failed", error=err[:300])
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr=f"Git clone failed: {err}",
                tests_passed=0,
                tests_failed=0,
                tests_errored=0,
                duration_ms=int(time.time() * 1000) - start_ms,
                timed_out=False,
                container_id=None,
            )

        # ── Step 2: Apply patched file ─────────────────────────────────────
        target_path = os.path.join(workdir, file_path.lstrip("/"))
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(patched_code)

        logger.info("sandbox_patch_applied", file=file_path)

        # ── Step 3: Run Docker container ───────────────────────────────────
        client = _get_docker_client()

        container_name = f"secops-sandbox-{uuid.uuid4().hex[:8]}"

        logger.info("sandbox_container_starting", name=container_name)

        container = client.containers.run(
            image=settings.sandbox_base_image,
            command="bash -c 'pip install -r requirements.txt -q 2>/dev/null; pytest --tb=short -q 2>&1'",
            volumes={workdir: {"bind": "/workspace", "mode": "rw"}},
            working_dir="/workspace",
            name=container_name,
            detach=True,
            network_disabled=True,           # ← Zero exfiltration
            mem_limit=settings.sandbox_memory_limit,
            cpu_quota=settings.sandbox_cpu_quota,
            cpu_period=100000,
            read_only=False,
            remove=False,                    # We'll remove manually after reading logs
            stdout=True,
            stderr=True,
            environment={
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "CI": "true",
            },
        )

        container_id = container.id[:12]
        logger.info("sandbox_container_started", container_id=container_id)

        # ── Step 4: Wait with hard timeout ─────────────────────────────────
        timed_out = False
        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: container.wait(timeout=settings.sandbox_timeout_seconds),
                ),
                timeout=settings.sandbox_timeout_seconds + 5,
            )
            exit_code: int = result.get("StatusCode", 1)
        except (asyncio.TimeoutError, Exception):
            timed_out = True
            exit_code = 1
            logger.warning("sandbox_container_timeout", container_id=container_id)
            try:
                container.kill()
            except Exception:
                pass

        # ── Step 5: Collect logs ───────────────────────────────────────────
        try:
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        except Exception:
            logs = ""

        stdout = logs
        stderr = ""

        # ── Step 6: Parse pytest output ────────────────────────────────────
        parsed = parse_pytest_output(stdout)

        duration_ms = int(time.time() * 1000) - start_ms
        logger.info(
            "sandbox_complete",
            container_id=container_id,
            exit_code=exit_code,
            tests_passed=parsed["passed"],
            tests_failed=parsed["failed"],
            duration_ms=duration_ms,
            timed_out=timed_out,
        )

        return SandboxResult(
            exit_code=exit_code,
            stdout=stdout[:10_000],   # Cap at 10KB
            stderr=stderr[:2_000],
            tests_passed=parsed["passed"],
            tests_failed=parsed["failed"],
            tests_errored=parsed["errored"],
            duration_ms=duration_ms,
            timed_out=timed_out,
            container_id=container_id,
        )

    except Exception as exc:
        duration_ms = int(time.time() * 1000) - start_ms
        logger.error("sandbox_unexpected_error", error=str(exc), duration_ms=duration_ms)
        return SandboxResult(
            exit_code=1,
            stdout="",
            stderr=f"Sandbox controller error: {exc}",
            tests_passed=0,
            tests_failed=0,
            tests_errored=1,
            duration_ms=duration_ms,
            timed_out=False,
            container_id=None,
        )

    finally:
        # ── Cleanup ───────────────────────────────────────────────────────
        if container:
            try:
                container.remove(force=True)
                logger.info("sandbox_container_removed", container_id=container.id[:12])
            except Exception:
                pass
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass

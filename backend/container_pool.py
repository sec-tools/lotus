"""
Container Pool Manager for Lotus BDAAS Lab Infrastructure.

Provides lifecycle management for disposable lab containers used during
dynamic vulnerability testing. Supports both Docker CLI (local) and
abstracts future Kubernetes Job creation.
"""

import json
import subprocess
from typing import Dict, List, Optional, Any


class ContainerPool:
    """Manages disposable lab containers for vulnerability testing.

    Uses Docker CLI via subprocess for container operations.
    Gracefully handles Docker not being available.
    """

    def __init__(self, prefix: str = "lotus-lab"):
        self._prefix = prefix
        self._docker_available: Optional[bool] = None

    def _check_docker(self) -> bool:
        """Check if Docker CLI is available."""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=5,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            self._docker_available = False
        return self._docker_available

    def get_or_create_lab(self, repo_id: int, image: str = "lotus-lab-ubuntu:26.04") -> Dict[str, Any]:
        """Get existing lab container or create a new one with network isolation."""
        container_name = f"{self._prefix}-{repo_id}"
        if not self._check_docker():
            return {"name": container_name, "status": "docker_unavailable", "running": False}

        try:
            # Check if container already exists
            result = subprocess.run(
                ["docker", "ps", "-a", "-q", "-f", f"name={container_name}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip():
                # Container exists, start if stopped
                subprocess.run(
                    ["docker", "start", container_name],
                    capture_output=True, text=True, timeout=15,
                )
                return {"name": container_name, "status": "running", "running": True, "reused": True}

            # Create new container with network isolation and resource limits
            result = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", container_name,
                    "--network=none",
                    "--memory=4g", "--cpus=2",
                    "--security-opt", "no-new-privileges",
                    image,
                ],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                return {"name": container_name, "status": "created", "running": True, "reused": False}
            return {"name": container_name, "status": "create_failed", "running": False, "error": result.stderr[:200]}
        except Exception as e:
            return {"name": container_name, "status": "error", "running": False, "error": str(e)[:200]}

    def destroy_lab(self, repo_id: int) -> Dict[str, Any]:
        """Forcefully remove a lab container."""
        container_name = f"{self._prefix}-{repo_id}"
        if not self._check_docker():
            return {"name": container_name, "destroyed": False, "error": "docker_unavailable"}

        try:
            result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True, text=True, timeout=15,
            )
            return {"name": container_name, "destroyed": result.returncode == 0}
        except Exception as e:
            return {"name": container_name, "destroyed": False, "error": str(e)[:200]}

    def list_labs(self) -> List[Dict[str, str]]:
        """List all active lab containers."""
        if not self._check_docker():
            return []
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Image}}",
                 "--filter", f"name={self._prefix}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
            labs = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                labs.append({
                    "name": parts[0] if len(parts) > 0 else "",
                    "status": parts[1] if len(parts) > 1 else "",
                    "image": parts[2] if len(parts) > 2 else "",
                })
            return labs
        except Exception:
            return []

    def health_check(self) -> Dict[str, Any]:
        """Check Docker daemon health and available resources."""
        health: Dict[str, Any] = {"docker_available": False}
        if not self._check_docker():
            return health

        health["docker_available"] = True
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .}}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                try:
                    info = json.loads(result.stdout)
                    health["containers_running"] = info.get("ContainersRunning", 0)
                    health["containers_total"] = info.get("Containers", 0)
                    health["images"] = info.get("Images", 0)
                    health["memory_total"] = info.get("MemTotal", 0)
                except (json.JSONDecodeError, Exception):
                    pass
        except Exception:
            pass
        return health

    def get_container_status(self, repo_id: int) -> Dict[str, Any]:
        """Get detailed status for a specific lab container."""
        container_name = f"{self._prefix}-{repo_id}"
        if not self._check_docker():
            return {"name": container_name, "running": False, "status": "docker_unavailable"}

        try:
            result = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{.State.Status}}|{{.State.Running}}|{{.Config.Image}}",
                 container_name],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split("|")
                return {
                    "name": container_name,
                    "status": parts[0] if len(parts) > 0 else "unknown",
                    "running": parts[1].lower() == "true" if len(parts) > 1 else False,
                    "image": parts[2] if len(parts) > 2 else "",
                }
            return {"name": container_name, "running": False, "status": "not_found"}
        except Exception as e:
            return {"name": container_name, "running": False, "status": "error", "error": str(e)[:200]}

"""
Kernox — Container-Aware Process Tracking

Enriches process events with container context by reading
/proc/{pid}/cgroup and /proc/{pid}/ns/ information.

Detects:
  - Whether a process is running inside a container (Docker/LXC/K8s)
  - Container ID extraction from cgroup paths
  - Namespace isolation detection
"""

import os
import re

from agent.logging_config import logger

# Match Docker container IDs in cgroup paths
# e.g. /docker/abc123def456... or /kubepods/pod-xxx/abc123def456...
_CONTAINER_ID_RE = re.compile(r"[a-f0-9]{12,64}")
_DOCKER_CGROUP_RE = re.compile(r"/docker/([a-f0-9]{12,64})")
_K8S_CGROUP_RE = re.compile(r"/kubepods/.+/([a-f0-9]{12,64})")
_LXC_CGROUP_RE = re.compile(r"/lxc/([^/]+)")

# Host PID namespace inode (read once at startup)
_HOST_PID_NS = None


def _get_host_pid_ns() -> int | None:
    """Get the PID namespace inode of PID 1 (host namespace)."""
    global _HOST_PID_NS
    if _HOST_PID_NS is None:
        try:
            ns_link = os.readlink("/proc/1/ns/pid")
            # Format: pid:[4026531836]
            match = re.search(r"\[(\d+)\]", ns_link)
            if match:
                _HOST_PID_NS = int(match.group(1))
        except (OSError, PermissionError):
            pass
    return _HOST_PID_NS


def get_container_info(pid: int) -> dict:
    """
    Extract container context for a given PID.

    Returns a dict with:
      - is_container: bool
      - container_id: str or None (first 12 chars)
      - container_runtime: "docker" | "kubernetes" | "lxc" | None
      - pid_namespace: str (namespace inode)
    """
    result = {
        "is_container": False,
        "container_id": None,
        "container_runtime": None,
        "pid_namespace": None,
    }

    # Read PID namespace
    try:
        ns_link = os.readlink(f"/proc/{pid}/ns/pid")
        match = re.search(r"\[(\d+)\]", ns_link)
        if match:
            ns_inode = int(match.group(1))
            result["pid_namespace"] = str(ns_inode)

            # If different from host PID ns, it's containerized
            host_ns = _get_host_pid_ns()
            if host_ns and ns_inode != host_ns:
                result["is_container"] = True
    except (OSError, PermissionError):
        pass

    # Read cgroup info for container ID
    try:
        cgroup_path = f"/proc/{pid}/cgroup"
        with open(cgroup_path) as f:
            cgroup_data = f.read()

        # Check Docker
        m = _DOCKER_CGROUP_RE.search(cgroup_data)
        if m:
            result["is_container"] = True
            result["container_id"] = m.group(1)[:12]
            result["container_runtime"] = "docker"
            return result

        # Check Kubernetes
        m = _K8S_CGROUP_RE.search(cgroup_data)
        if m:
            result["is_container"] = True
            result["container_id"] = m.group(1)[:12]
            result["container_runtime"] = "kubernetes"
            return result

        # Check LXC
        m = _LXC_CGROUP_RE.search(cgroup_data)
        if m:
            result["is_container"] = True
            result["container_id"] = m.group(1)[:12]
            result["container_runtime"] = "lxc"
            return result

    except (OSError, PermissionError):
        pass

    return result


def enrich_event_with_container(event_data: dict, pid: int) -> dict:
    """
    Add container context to an event dict.
    Called by monitors before emitting events.
    """
    try:
        container = get_container_info(pid)
        if container["is_container"]:
            event_data["container"] = container
    except Exception:
        pass
    return event_data

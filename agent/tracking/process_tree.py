"""
Kernox — Process Lineage Tree

In-memory DAG that tracks parent→child process relationships.
Provides lineage queries (full ancestor chain) for attack graph building.
"""

import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProcessNode:
    """A single process in the lineage tree."""
    pid: int
    ppid: int
    comm: str
    cmdline: str = ""
    uid: int = 0
    username: str = ""
    alive: bool = True
    children: list = field(default_factory=list)


class ProcessTree:
    """
    Thread-safe in-memory process tree.

    Maintains a dict of PID → ProcessNode and tracks parent→child edges.
    Supports lineage queries and auto-prunes dead leaf processes to
    bound memory usage.
    """

    def __init__(self, max_size: int = 10000):
        self._lock = threading.Lock()
        self._nodes: dict[int, ProcessNode] = {}
        self._max_size = max_size

    # ── Mutations ────────────────────────────────────────────────

    def add_process(
        self,
        pid: int,
        ppid: int,
        comm: str,
        cmdline: str = "",
        uid: int = 0,
        username: str = "",
    ) -> None:
        """Register a new process execution event."""
        with self._lock:
            node = ProcessNode(
                pid=pid,
                ppid=ppid,
                comm=comm,
                cmdline=cmdline,
                uid=uid,
                username=username,
            )
            self._nodes[pid] = node

            # Link to parent if it exists
            parent = self._nodes.get(ppid)
            if parent and pid not in parent.children:
                parent.children.append(pid)

            # Prune if we exceed the size limit
            if len(self._nodes) > self._max_size:
                self._prune_dead_leaves()

    def remove_process(self, pid: int) -> None:
        """Mark a process as exited. Prune if it's a childless leaf."""
        with self._lock:
            node = self._nodes.get(pid)
            if node is None:
                return
            node.alive = False

            # If this dead process has no living children, prune it
            if not any(
                self._nodes.get(c, ProcessNode(0, 0, "")).alive
                for c in node.children
            ):
                self._remove_leaf(pid)

    # ── Queries ──────────────────────────────────────────────────

    def get_lineage(self, pid: int, max_depth: int = 20) -> list[dict]:
        """
        Get the full ancestor chain for a PID.

        Returns a list from oldest ancestor → target process, e.g.:
        [
            {"pid": 1, "comm": "systemd"},
            {"pid": 1234, "comm": "bash"},
            {"pid": 5678, "comm": "curl"},
        ]
        """
        with self._lock:
            chain = []
            visited = set()
            current_pid = pid
            depth = 0

            while current_pid in self._nodes and depth < max_depth:
                if current_pid in visited:
                    break  # Prevent cycles
                visited.add(current_pid)
                node = self._nodes[current_pid]
                chain.append({
                    "pid": node.pid,
                    "comm": node.comm,
                    "cmdline": node.cmdline,
                })
                current_pid = node.ppid
                depth += 1

            chain.reverse()
            return chain

    def get_lineage_string(self, pid: int) -> str:
        """Return a human-readable lineage string like 'bash → curl → sh'."""
        chain = self.get_lineage(pid)
        if not chain:
            return "unknown"
        return " → ".join(entry["comm"] for entry in chain)

    def get_children(self, pid: int) -> list[int]:
        """Get all direct child PIDs of a process."""
        with self._lock:
            node = self._nodes.get(pid)
            if node is None:
                return []
            return list(node.children)

    def get_process(self, pid: int) -> Optional[ProcessNode]:
        """Get a process node by PID."""
        with self._lock:
            return self._nodes.get(pid)

    @property
    def size(self) -> int:
        """Number of tracked processes."""
        return len(self._nodes)

    # ── Debug ────────────────────────────────────────────────────

    def print_tree(self, root_pid: int = 1, indent: int = 0) -> str:
        """Return a text representation of the process tree."""
        lines = []
        self._print_subtree(root_pid, indent, lines, set())
        return "\n".join(lines) if lines else "(empty tree)"

    def _print_subtree(
        self, pid: int, indent: int, lines: list, visited: set
    ) -> None:
        if pid in visited:
            return
        visited.add(pid)

        node = self._nodes.get(pid)
        if node is None:
            return

        status = "●" if node.alive else "○"
        prefix = "  " * indent
        lines.append(f"{prefix}{status} [{node.pid}] {node.comm}")

        for child_pid in node.children:
            self._print_subtree(child_pid, indent + 1, lines, visited)

    # ── Internal ─────────────────────────────────────────────────

    def _remove_leaf(self, pid: int) -> None:
        """Remove a dead leaf node and unlink from parent."""
        node = self._nodes.get(pid)
        if node is None:
            return

        # Remove from parent's children list
        parent = self._nodes.get(node.ppid)
        if parent and pid in parent.children:
            parent.children.remove(pid)

        del self._nodes[pid]

    def _prune_dead_leaves(self) -> None:
        """Remove dead processes that have no living children."""
        to_remove = []
        for pid, node in self._nodes.items():
            if not node.alive:
                living_children = [
                    c for c in node.children
                    if c in self._nodes and self._nodes[c].alive
                ]
                if not living_children:
                    to_remove.append(pid)

        for pid in to_remove:
            self._remove_leaf(pid)

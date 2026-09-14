from __future__ import annotations
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

"""
5-Tier Memory Architecture for the Lotus AI Security Harness.

Tier 1 - Working Memory: Per-iteration scratchpad (AST slice, active PoC, compiler errors).
Tier 2 - Episodic Memory: Audit session trajectory (hypothesis history, probe outputs, conviction levels).
Tier 3 - Topological Memory: AST/CPG graph cache (call graphs, reachability paths, guard maps).
Tier 4 - Negative Memory: Hypothesis graveyard with fingerprints of disproven leads.
Tier 5 - Compounding Skill Memory: Already exists in backend/skills.py - not duplicated here.
"""

class WorkingMemory:
    def __init__(self):
        self._store: Dict[str, Any] = {}

    def set(self, key: str, value: Any):
        self._store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def set_slice(self, finding_key: str, code_slice: str):
        self.set(f"slice:{finding_key}", code_slice)

    def get_slice(self, finding_key: str) -> Optional[str]:
        return self.get(f"slice:{finding_key}")

    def set_poc(self, finding_key: str, poc_code: str):
        self.set(f"poc:{finding_key}", poc_code)

    def get_poc(self, finding_key: str) -> Optional[str]:
        return self.get(f"poc:{finding_key}")

    def set_error(self, finding_key: str, error: str):
        self.set(f"error:{finding_key}", error)

    def get_error(self, finding_key: str) -> Optional[str]:
        return self.get(f"error:{finding_key}")

    def evict(self):
        self._store.clear()

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._store)

class EpisodicMemory:
    def __init__(self):
        self._trajectory: List[Dict[str, Any]] = []

    def record(self, event_type: str, finding_key: str, data: Dict[str, Any]):
        self._trajectory.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "finding_key": finding_key,
            "data": data
        })

    def get_trajectory(self) -> List[Dict[str, Any]]:
        return list(self._trajectory)

    def get_events_for(self, finding_key: str) -> List[Dict[str, Any]]:
        return [e for e in self._trajectory if e["finding_key"] == finding_key]

    def conviction_history(self, finding_key: str) -> List[int]:
        events = self.get_events_for(finding_key)
        history = []
        for e in events:
            if "conviction" in e.get("data", {}):
                history.append(e["data"]["conviction"])
        return history

    def iteration_count(self) -> int:
        return len({e["data"].get("iteration_id") for e in self._trajectory if "iteration_id" in e.get("data", {})})

    def summary(self) -> Dict[str, Any]:
        counts = {}
        for e in self._trajectory:
            counts[e["event_type"]] = counts.get(e["event_type"], 0) + 1
        return counts

class TopologicalMemory:
    def __init__(self):
        self._graph: Optional[Dict[str, Any]] = None
        self._functions: Dict[str, Any] = {}
        self._caller_map: Dict[str, List[str]] = {}

    def load_from_callgraph(self, call_graph_result: Dict[str, Any]):
        self._graph = call_graph_result
        self._functions = call_graph_result.get("functions", {})
        self._build_caller_map()

    def build(self, dest: Path, language: str):
        from backend.callgraph import build_call_graph
        result = build_call_graph(dest, language)
        self.load_from_callgraph(result)

    def _build_caller_map(self):
        self._caller_map = {}
        for func_name, meta in self._functions.items():
            for callee in meta.get("calls", []):
                if callee not in self._caller_map:
                    self._caller_map[callee] = []
                if func_name not in self._caller_map[callee]:
                    self._caller_map[callee].append(func_name)

    def reachable_sinks(self, entrypoint: str) -> List[str]:
        sinks = set()
        visited = set()
        queue = [entrypoint]
        
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            meta = self._functions.get(curr, {})
            if meta.get("has_sink"):
                sinks.add(curr)
            for callee in meta.get("calls", []):
                if callee not in visited:
                    queue.append(callee)
        return list(sinks)

    def callers_of(self, func_name: str) -> List[str]:
        return self._caller_map.get(func_name, [])

    def get_function_meta(self, func_name: str) -> Optional[Dict]:
        return self._functions.get(func_name)

    def function_count(self) -> int:
        return len(self._functions)

    def taint_path_count(self) -> int:
        if not self._graph:
            return 0
        tp = self._graph.get("taint_paths")
        if isinstance(tp, list):
            return len(tp)
        return 0

    def slice_context(self, sink_func: str, max_hops: int = 3) -> List[Dict]:
        context = []
        curr = sink_func
        hops = 0
        while curr and hops < max_hops:
            meta = self.get_function_meta(curr)
            if meta:
                context.append(meta)
            callers = self.callers_of(curr)
            if callers:
                curr = callers[0]
                hops += 1
            else:
                break
        return context

class NegativeMemory:
    def __init__(self, persistence_path: Optional[Path] = None):
        self._fingerprints: Dict[str, Dict] = {}
        self.persistence_path = persistence_path

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        file = finding.get("file", "")
        line = str(finding.get("line", ""))
        title = finding.get("title", "")
        data = f"{file}:{line}:{title}".encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def is_disproven(self, finding: Dict[str, Any]) -> bool:
        return self._fingerprint(finding) in self._fingerprints

    def record_disproven(self, finding: Dict[str, Any], kill_reason: str):
        fp = self._fingerprint(finding)
        self._fingerprints[fp] = {
            "kill_reason": kill_reason,
            "timestamp": datetime.utcnow().isoformat(),
            "finding": finding
        }

    def get_kill_reason(self, finding: Dict[str, Any]) -> Optional[str]:
        fp = self._fingerprint(finding)
        entry = self._fingerprints.get(fp)
        return entry["kill_reason"] if entry else None

    def count(self) -> int:
        return len(self._fingerprints)

    def save(self):
        if self.persistence_path:
            with open(self.persistence_path, "w") as f:
                json.dump(self._fingerprints, f, indent=2)

    def load(self):
        if self.persistence_path and self.persistence_path.exists():
            with open(self.persistence_path, "r") as f:
                self._fingerprints = json.load(f)

    def all_entries(self) -> Dict[str, Dict]:
        return self._fingerprints

class HarnessMemoryManager:
    def __init__(self, dest: Path, language: str, persistence_dir: Optional[Path] = None):
        self._working = WorkingMemory()
        self._episodic = EpisodicMemory()
        self._topological = TopologicalMemory()
        
        neg_path = None
        if persistence_dir:
            persistence_dir.mkdir(parents=True, exist_ok=True)
            neg_path = persistence_dir / "negative_memory.json"
        self._negative = NegativeMemory(neg_path)
        
        self._topological.build(dest, language)
        self._negative.load()

    @property
    def working(self) -> WorkingMemory:
        return self._working

    @property
    def episodic(self) -> EpisodicMemory:
        return self._episodic

    @property
    def topological(self) -> TopologicalMemory:
        return self._topological

    @property
    def negative(self) -> NegativeMemory:
        return self._negative

    def new_iteration(self):
        self._working.evict()
        iter_id = self._episodic.iteration_count() + 1
        self._episodic.record("iteration_start", "global", {"iteration_id": iter_id})

    def finalize(self):
        self._negative.save()

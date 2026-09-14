"""
Modular, hot-swappable Skill Pack registry for Lotus.

Packs are versioned skill collections that can be enabled/disabled without
restarting the platform. Defaults ship as `lotus-core` (methodology/discovery/
gating/bug-classes seeds). Learned skills from confirmed findings land in the
`learned` pack so discovery compounds across audits.

Layout:
  data/skills/
    packs/
      lotus-core/pack.yaml   # optional overlay; defaults resolve to category dirs
      learned/pack.yaml
      <custom>/...
    methodology/ ...         # lotus-core content (compat with existing layout)
    discovery/
    gating/
    bug-classes/
    learned/                 # auto-written skills (preferred)
    *.md                     # legacy root learned skills (still loaded)
    pattern_db.json
    packs_state.json         # enabled pack ids + order
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

SKILLS_DIR = Path(os.environ.get("LOTUS_SKILLS_DIR", "./data/skills"))

_lock = threading.RLock()
_cache: Optional["SkillPackRegistry"] = None


def _skills_dir() -> Path:
    return Path(os.environ.get("LOTUS_SKILLS_DIR", str(SKILLS_DIR)))


def _packs_dir() -> Path:
    return _skills_dir() / "packs"


def _state_file() -> Path:
    return _skills_dir() / "packs_state.json"


@dataclass
class SkillPack:
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    enabled: bool = True
    priority: int = 100  # lower = loaded first
    path: str = ""
    categories: List[str] = field(default_factory=lambda: [
        "methodology", "gating", "discovery", "bug-classes", "learned",
    ])
    builtin: bool = False
    skill_count: int = 0

    def root(self) -> Path:
        return Path(self.path) if self.path else SKILLS_DIR


def _learned_pack_root() -> str:
    """Learned pack is pinned to the platform skills home, not the BYOS doctrine root."""
    try:
        from backend.skills import get_learned_dir
        return str(get_learned_dir().parent)
    except Exception:
        return str(_skills_dir())


def _external_state_file() -> Path:
    try:
        from backend.skills import get_platform_home
        return get_platform_home() / "external_packs.json"
    except Exception:
        return _skills_dir() / "external_packs.json"


def _default_packs() -> List[SkillPack]:
    root = str(_skills_dir())
    learned_root = _learned_pack_root()
    return [
        SkillPack(
            id="lotus-core",
            name="Lotus Core Methodology",
            version="1.1.0",
            description=(
                "Default audit-markdown-light doctrine: T1–T11, sink-first, "
                "guard-alternate-path, severity honesty, FP gating, bug classes."
            ),
            enabled=True,
            priority=10,
            path=root,
            categories=["methodology", "gating", "discovery", "bug-classes"],
            builtin=True,
        ),
        SkillPack(
            id="learned",
            name="Learned Skills (compounding)",
            version="1.0.0",
            description=(
                "Auto-generated skills from confirmed findings + pattern_db. "
                "Grows with every successful audit."
            ),
            enabled=True,
            priority=50,
            path=learned_root,
            categories=["learned"],
            builtin=True,
        ),
    ]


class SkillPackRegistry:
    """Discover, enable/disable, and resolve skill pack roots."""

    def __init__(self, skills_dir: Optional[Path] = None):
        self.skills_dir = Path(skills_dir) if skills_dir else _skills_dir()
        self.packs_dir = self.skills_dir / "packs"
        self.state_file = self.skills_dir / "packs_state.json"
        self._packs: Dict[str, SkillPack] = {}
        self.reload()

    def reload(self) -> None:
        with _lock:
            self._packs = {p.id: p for p in _default_packs()}
            # Ensure directories exist
            self.skills_dir.mkdir(parents=True, exist_ok=True)
            Path(_learned_pack_root()).mkdir(parents=True, exist_ok=True)
            (Path(_learned_pack_root()) / "learned").mkdir(parents=True, exist_ok=True)
            self.packs_dir.mkdir(parents=True, exist_ok=True)

            # Discover overlay packs under packs/
            if self.packs_dir.exists():
                for child in sorted(self.packs_dir.iterdir()):
                    if not child.is_dir():
                        continue
                    meta = self._read_pack_yaml(child)
                    if not meta:
                        continue
                    pid = meta.get("id") or child.name
                    # Builtin content packs keep skills_dir as root; overlay dir is metadata-only
                    if pid in ("lotus-core", "learned"):
                        path = _learned_pack_root() if pid == "learned" else str(self.skills_dir)
                        cats = list(meta.get("categories") or self._packs.get(pid).categories) if pid in self._packs else [
                            "methodology", "gating", "discovery", "bug-classes"
                        ] if pid == "lotus-core" else ["learned"]
                    else:
                        path = str(child)
                        cats = list(meta.get("categories") or [
                            "methodology", "gating", "discovery", "bug-classes", "learned",
                        ])
                    self._packs[pid] = SkillPack(
                        id=pid,
                        name=meta.get("name", pid),
                        version=str(meta.get("version", "1.0.0")),
                        description=meta.get("description", ""),
                        enabled=bool(meta.get("enabled", True)),
                        priority=int(meta.get("priority", 100)),
                        path=path,
                        categories=cats,
                        builtin=pid in ("lotus-core", "learned"),
                    )

            # Apply persisted enable/priority state
            state = self._load_state()
            for pid, cfg in (state.get("packs") or {}).items():
                if pid in self._packs:
                    if "enabled" in cfg:
                        self._packs[pid].enabled = bool(cfg["enabled"])
                    if "priority" in cfg:
                        self._packs[pid].priority = int(cfg["priority"])
            # Rehydrate external packs whose paths live on the platform home
            ext_state = self._load_external_state()
            for pid, cfg in (ext_state.get("packs") or {}).items():
                pth = Path(str(cfg.get("path") or ""))
                if not pth.is_dir():
                    continue
                existing = self._packs.get(pid)
                if existing and existing.builtin:
                    continue
                self._packs[pid] = SkillPack(
                    id=pid,
                    name=str(cfg.get("name") or pid),
                    version=str(cfg.get("version") or "custom"),
                    description=str(cfg.get("description") or f"External pack at {pth}"),
                    enabled=bool(cfg.get("enabled", True)),
                    priority=int(cfg.get("priority", 80)),
                    path=str(pth.resolve()),
                    categories=list(cfg.get("categories") or [
                        "methodology", "gating", "discovery", "bug-classes", "learned",
                    ]),
                    builtin=False,
                )

            # Env override: LOTUS_SKILL_PACKS=lotus-core,learned,my-pack
            env_packs = os.environ.get("LOTUS_SKILL_PACKS", "").strip()
            if env_packs:
                wanted = {x.strip() for x in env_packs.split(",") if x.strip()}
                for pid, pack in self._packs.items():
                    pack.enabled = pid in wanted

            self._refresh_counts()

    def _read_pack_yaml(self, pack_dir: Path) -> Optional[dict]:
        for name in ("pack.yaml", "pack.yml", "pack.json"):
            f = pack_dir / name
            if not f.exists():
                continue
            try:
                text = f.read_text(encoding="utf-8")
                if name.endswith(".json"):
                    return json.loads(text)
                # Minimal YAML subset (key: value)
                data: Dict[str, Any] = {}
                current_list_key = None
                for line in text.splitlines():
                    if not line.strip() or line.strip().startswith("#"):
                        continue
                    if line.lstrip().startswith("- ") and current_list_key:
                        data.setdefault(current_list_key, []).append(
                            line.split("- ", 1)[1].strip().strip("\"'")
                        )
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k, v = k.strip(), v.strip().strip("\"'")
                        if not v:
                            current_list_key = k
                            data[k] = []
                        else:
                            current_list_key = None
                            if v.lower() in ("true", "false"):
                                data[k] = v.lower() == "true"
                            else:
                                try:
                                    data[k] = int(v)
                                except ValueError:
                                    data[k] = v
                return data
            except Exception:
                continue
        return None

    def _load_external_state(self) -> dict:
        f = _external_state_file()
        if not f.exists():
            return {}
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_external_state(self) -> None:
        payload = {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "packs": {
                pid: {
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "enabled": p.enabled,
                    "priority": p.priority,
                    "path": p.path,
                    "categories": list(p.categories),
                }
                for pid, p in self._packs.items()
                if not p.builtin
            },
        }
        f = _external_state_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load_state(self) -> dict:
        if not self.state_file.exists():
            return {}
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self) -> None:
        payload = {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "packs": {
                pid: {"enabled": p.enabled, "priority": p.priority}
                for pid, p in self._packs.items()
            },
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _refresh_counts(self) -> None:
        for pack in self._packs.values():
            pack.skill_count = len(self.list_skill_files(pack))

    def list_packs(self) -> List[SkillPack]:
        return sorted(self._packs.values(), key=lambda p: (p.priority, p.id))

    def get(self, pack_id: str) -> Optional[SkillPack]:
        return self._packs.get(pack_id)

    def set_enabled(self, pack_id: str, enabled: bool) -> SkillPack:
        pack = self._packs.get(pack_id)
        if not pack:
            raise KeyError(f"Unknown skill pack: {pack_id}")
        pack.enabled = enabled
        self._save_state()
        return pack

    def set_priority(self, pack_id: str, priority: int) -> SkillPack:
        pack = self._packs.get(pack_id)
        if not pack:
            raise KeyError(f"Unknown skill pack: {pack_id}")
        pack.priority = int(priority)
        self._save_state()
        return pack

    def register_external(self, pack_id: str, path: str, name: str = "", enabled: bool = True) -> SkillPack:
        """Hot-add a custom pack from an arbitrary directory."""
        p = Path(path)
        if not p.is_dir():
            raise ValueError(f"Pack path is not a directory: {path}")
        pack = SkillPack(
            id=pack_id,
            name=name or pack_id,
            version="custom",
            description=f"External pack at {path}",
            enabled=enabled,
            priority=80,
            path=str(p.resolve()),
            categories=["methodology", "gating", "discovery", "bug-classes", "learned"],
            builtin=False,
        )
        self._packs[pack_id] = pack
        self._refresh_counts()
        self._save_state()
        self._save_external_state()
        return pack

    def enabled_packs(self) -> List[SkillPack]:
        return [p for p in self.list_packs() if p.enabled]

    def list_skill_files(self, pack: Optional[SkillPack] = None) -> List[Path]:
        packs = [pack] if pack else self.enabled_packs()
        files: List[Path] = []
        seen = set()
        for pk in packs:
            root = pk.root()
            for cat in pk.categories:
                if cat == "learned":
                    # Preferred learned/ dir + legacy root *.md
                    learned_dir = root / "learned"
                    if learned_dir.exists():
                        for f in sorted(learned_dir.glob("*.md")):
                            if f.resolve() not in seen:
                                seen.add(f.resolve())
                                files.append(f)
                    if pk.id == "learned":
                        for f in sorted(root.glob("*.md")):
                            if f.resolve() not in seen:
                                seen.add(f.resolve())
                                files.append(f)
                else:
                    cat_dir = root / cat
                    if cat_dir.exists():
                        for f in sorted(cat_dir.glob("*.md")):
                            if f.resolve() not in seen:
                                seen.add(f.resolve())
                                files.append(f)
            # Also load pack-local proof/harness skills (e.g. packs/lotus-core/*.md)
            pack_overlay = self.packs_dir / pk.id
            if pack_overlay.is_dir():
                for f in sorted(pack_overlay.glob("*.md")):
                    if f.name.lower() == "readme.md":
                        continue
                    if f.resolve() not in seen:
                        seen.add(f.resolve())
                        files.append(f)
        return files

    def to_dict(self) -> List[dict]:
        self._refresh_counts()
        return [asdict(p) for p in self.list_packs()]


def get_registry(force_reload: bool = False, **kwargs) -> SkillPackRegistry:
    global _cache
    reload = bool(force_reload or kwargs.get("force_reload"))
    with _lock:
        if _cache is None or reload:
            _cache = SkillPackRegistry()
        return _cache


def ensure_default_packs_seeded() -> int:
    """Seed lotus-core onto the platform home only — never into a BYOS doctrine root."""
    from backend.skill_seeds import seed_all
    try:
        from backend.skills import get_platform_home
        root = get_platform_home()
    except Exception:
        root = _skills_dir()
    root.mkdir(parents=True, exist_ok=True)
    Path(_learned_pack_root()).mkdir(parents=True, exist_ok=True)
    (Path(_learned_pack_root()) / "learned").mkdir(parents=True, exist_ok=True)
    packs_dir = root / "packs"
    packs_dir.mkdir(parents=True, exist_ok=True)
    # Write default pack manifests for discoverability
    core_dir = packs_dir / "lotus-core"
    core_dir.mkdir(parents=True, exist_ok=True)
    core_manifest = core_dir / "pack.yaml"
    if not core_manifest.exists():
        core_manifest.write_text(
            "id: lotus-core\n"
            "name: Lotus Core Methodology\n"
            "version: \"1.1.0\"\n"
            "enabled: true\n"
            "priority: 10\n"
            "description: Default audit methodology pack (audit-markdown-light distilled)\n"
            "categories:\n"
            "  - methodology\n"
            "  - gating\n"
            "  - discovery\n"
            "  - bug-classes\n",
            encoding="utf-8",
        )
        readme = core_dir / "README.md"
        readme.write_text(
            "lotus-core content is stored in ../../{methodology,discovery,gating,bug-classes}/ "
            "for backward compatibility. Enable/disable via Skill Pack registry.\n",
            encoding="utf-8",
        )

    learned_dir = packs_dir / "learned"
    learned_dir.mkdir(parents=True, exist_ok=True)
    learned_manifest = learned_dir / "pack.yaml"
    if not learned_manifest.exists():
        learned_manifest.write_text(
            "id: learned\n"
            "name: Learned Skills\n"
            "version: \"1.0.0\"\n"
            "enabled: true\n"
            "priority: 50\n"
            "description: Auto-generated skills from confirmed findings\n"
            "categories:\n"
            "  - learned\n",
            encoding="utf-8",
        )

    seeded = seed_all(root)
    get_registry(force_reload=True)
    return seeded

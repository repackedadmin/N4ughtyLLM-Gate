"""
Bootstrap required config on first run: if config/.env or policy YAML is missing at runtime,
copy from built-in defaults so Docker mounts and local starts work without manual setup.
Call from app startup or run: python -m n4ughtyllm_gate.init_config
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

from n4ughtyllm_gate.config.settings import settings
from n4ughtyllm_gate.util.logger import logger

# Policy YAML that must exist (copied from bootstrap if missing)
_POLICY_YAML = ("default.yaml", "permissive.yaml", "strict.yaml")
_SECURITY_RULES_YAML = "security_filters.yaml"
_REQUIRED_YAML = (*_POLICY_YAML, _SECURITY_RULES_YAML)
# Packaged policy directory
_PACKAGE_RULES_DIR = Path(__file__).resolve().parent / "policies" / "rules"
# Project root (e.g. /app in image)
_APP_ROOT_DIR = Path(__file__).resolve().parent.parent
# Read-only bootstrap in image (not overwritten by rules volume mount)
_BOOTSTRAP_RULES_DIR = _APP_ROOT_DIR / "bootstrap" / "rules"
_ENV_EXAMPLE = ".env.example"
_RUNTIME_FALLBACK_DIR = Path("/tmp") / "n4ughtyllm_gate"


def _resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_absolute():
        return path
    candidates = [Path.cwd() / path, _APP_ROOT_DIR / path]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[-1].resolve()


def _config_dir() -> Path:
    if os.environ.get("N4UGHTYLLM_GATE_CONFIG_DIR"):
        return Path(os.environ["N4UGHTYLLM_GATE_CONFIG_DIR"]).resolve()
    return _resolve_path(settings.security_rules_path).parent


def _runtime_env_dir() -> Path:
    return (Path.cwd() / "config").resolve()


def _env_example_path() -> Path | None:
    """Resolve .env.example: cwd/config, then parent, then package parent (local dev)."""
    cwd = Path.cwd()
    for base in (cwd, cwd.parent, Path(__file__).resolve().parent.parent):
        p = base / "config" / _ENV_EXAMPLE
        if p.is_file():
            return p
    return None


def _rules_source_dir() -> Path | None:
    configured = os.environ.get("N4UGHTYLLM_GATE_BOOTSTRAP_RULES_DIR", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).resolve())
    candidates.extend((_BOOTSTRAP_RULES_DIR, _PACKAGE_RULES_DIR))
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        has_required = any((candidate / name).is_file() for name in _REQUIRED_YAML)
        if has_required:
            return candidate
    return None


def missing_required_rules(config_dir: Path | None = None) -> list[str]:
    rules_dir = config_dir or _config_dir()
    missing: list[str] = []
    for name in _REQUIRED_YAML:
        p = rules_dir / name
        if not p.exists() or p.stat().st_size == 0:
            missing.append(name)
    return missing


def _file_ready(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def _bootstrap_has_all_policy_rules() -> bool:
    src = _rules_source_dir()
    if src is None:
        return False
    return all(_file_ready(src / name) for name in _POLICY_YAML)


def _bootstrap_has_security_rules() -> bool:
    src = _rules_source_dir()
    if src is None:
        return False
    return _file_ready(src / _SECURITY_RULES_YAML)


def assert_security_bootstrap_ready(config_dir: Path | None = None) -> None:
    rules_dir = config_dir or _config_dir()
    missing: list[str] = []

    # If default.yaml is missing, PolicyEngine falls back to bootstrap for all policy files.
    if _file_ready(rules_dir / "default.yaml"):
        for name in _POLICY_YAML:
            if not _file_ready(rules_dir / name):
                missing.append(name)
    elif not _bootstrap_has_all_policy_rules():
        missing.extend(
            name for name in _POLICY_YAML if not _file_ready(rules_dir / name)
        )

    # security_filters.yaml is loaded separately; may fall back to bootstrap alone.
    if (
        not _file_ready(rules_dir / _SECURITY_RULES_YAML)
        and not _bootstrap_has_security_rules()
    ):
        missing.append(_SECURITY_RULES_YAML)

    if missing:
        raise RuntimeError(
            f"missing required security policy files in {rules_dir}: {', '.join(missing)}"
        )


def ensure_config_dir() -> None:
    """
    Copy missing required files from bootstrap; never overwrite non-empty files.
    Empty Docker-mounted dirs and first local start get populated the same way.
    """
    config_dir = _config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)

    # 1. Policy YAML from bootstrap / package rules
    src_dir = _rules_source_dir()
    if src_dir is not None:
        for name in _REQUIRED_YAML:
            src = src_dir / name
            dst = config_dir / name
            if not src.is_file():
                continue
            if not dst.exists() or dst.stat().st_size == 0:
                try:
                    shutil.copy2(src, dst)
                    logger.info("init_config: created %s from default", dst)
                except OSError as e:
                    logger.warning("init_config: could not write %s: %s", dst, e)
    else:
        logger.warning(
            "init_config: no bootstrap rules source found candidates=%s,%s",
            _BOOTSTRAP_RULES_DIR,
            _PACKAGE_RULES_DIR,
        )

    env_dir = _runtime_env_dir()
    env_dst = env_dir / ".env"
    if not env_dst.exists() or env_dst.stat().st_size == 0:
        env_src = _env_example_path()
        if env_src and env_src.is_file():
            try:
                env_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(env_src, env_dst)
                logger.info("init_config: created %s from %s", env_dst, env_src.name)
            except OSError as e:
                logger.warning("init_config: could not write %s: %s", env_dst, e)
        else:
            logger.debug("init_config: no .env.example found, skip creating .env")


def _can_append_file(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8"):
            pass
        return True
    except OSError:
        return False


def _can_use_sqlite_path(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path, timeout=1.0) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS __n4ughtyllm_gate_write_probe__(id INTEGER)"
            )
            conn.execute("DROP TABLE IF EXISTS __n4ughtyllm_gate_write_probe__")
            conn.commit()
        return True
    except (sqlite3.Error, OSError):
        return False


def ensure_runtime_storage_paths() -> None:
    """Ensure runtime-write paths are usable; fallback to /tmp when needed."""
    fallback_dir = _RUNTIME_FALLBACK_DIR
    fallback_dir.mkdir(parents=True, exist_ok=True)

    backend = (settings.storage_backend or "sqlite").strip().lower()
    if backend in {"", "sqlite"}:
        configured_db = Path(settings.sqlite_db_path)
        if not _can_use_sqlite_path(configured_db):
            fallback_db = fallback_dir / "n4ughtyllm_gate.db"
            if not _can_use_sqlite_path(fallback_db):
                raise RuntimeError(
                    "sqlite storage path is not writable and fallback also failed: "
                    f"configured={configured_db} fallback={fallback_db}"
                )
            settings.sqlite_db_path = str(fallback_db)
            logger.warning(
                "init_config: sqlite path not writable, switched to fallback configured=%s fallback=%s",
                configured_db,
                fallback_db,
            )

    audit_path = (settings.audit_log_path or "").strip()
    if audit_path:
        configured_audit = Path(audit_path)
        if not _can_append_file(configured_audit):
            fallback_audit = fallback_dir / "audit.jsonl"
            if _can_append_file(fallback_audit):
                settings.audit_log_path = str(fallback_audit)
                logger.warning(
                    "init_config: audit path not writable, switched to fallback configured=%s fallback=%s",
                    configured_audit,
                    fallback_audit,
                )
            else:
                settings.audit_log_path = ""
                logger.warning(
                    "init_config: audit path not writable and fallback failed, disable audit file configured=%s fallback=%s",
                    configured_audit,
                    fallback_audit,
                )

    dangerous_log_path = (settings.dangerous_response_log_path or "").strip()
    if dangerous_log_path:
        configured_dangerous = Path(dangerous_log_path)
        if not _can_append_file(configured_dangerous):
            fallback_dangerous = fallback_dir / "dangerous_responses.jsonl"
            if _can_append_file(fallback_dangerous):
                settings.dangerous_response_log_path = str(fallback_dangerous)
                logger.warning(
                    "init_config: dangerous response log path not writable, switched to fallback configured=%s fallback=%s",
                    configured_dangerous,
                    fallback_dangerous,
                )
            else:
                settings.dangerous_response_log_path = ""
                logger.warning(
                    "init_config: dangerous response log path not writable and fallback failed, disable dangerous response log configured=%s fallback=%s",
                    configured_dangerous,
                    fallback_dangerous,
                )


def main() -> None:
    """CLI entry or one-off container run."""
    ensure_config_dir()
    ensure_runtime_storage_paths()
    strict = os.environ.get("N4UGHTYLLM_GATE_INIT_STRICT", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    if strict:
        assert_security_bootstrap_ready()
        logger.info("init_config: security bootstrap ready")


if __name__ == "__main__":
    main()

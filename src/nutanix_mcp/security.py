"""Centralized security policy, runtime limits, and validated configuration."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache, wraps
from typing import Any


@dataclass(frozen=True)
class ToolSecurityPolicy:
    """Per-tool security controls."""

    request_timeout_seconds: float
    concurrency_limit: int
    rate_limit_per_minute: int


@dataclass(frozen=True)
class SecurityConfig:
    """Validated security configuration loaded once at startup."""

    default_tool_policy: ToolSecurityPolicy
    per_tool_policy: dict[str, ToolSecurityPolicy]


_PE_ALLOWED_BASE_PATHS = {
    "/PrismGateway/services/rest/v2.0",
    "/PrismGateway/services/rest/v1",
    "/api/nutanix/v0.8",
}

_PE_ALLOWED_PREFIXES_BY_BASE_PATH: dict[str, set[str]] = {
    "/PrismGateway/services/rest/v2.0": {
        "/alerts",
        "/cluster",
        "/disks",
        "/events",
        "/hosts",
        "/images",
        "/networks",
        "/protection_domains",
        "/storage_containers",
        "/vms",
    },
    "/PrismGateway/services/rest/v1": {
        "/storage_pools",
    },
    "/api/nutanix/v0.8": {
        "/tasks",
    },
}

_PC_ALLOWED_PREFIXES = {
    "/PrismGateway/services/rest/v2.0/alerts",
    "/api/clustermgmt/v4.0/config/clusters",
    "/api/clustermgmt/v4.0/config/hosts",
    "/api/clustermgmt/v4.0/config/storage-containers",
    "/api/monitoring/v4.0/alerts",
    "/api/monitoring/v4.0/services/alerts/alert-policies",
    "/api/networking/v4.0/config/subnets",
    "/api/prism/v4.0/config/categories",
    "/api/prism/v4.0/config/tasks",
    "/api/vmm/v4.0/ahv/config/vms",
    "/api/vmm/v4.0/content/images",
}

_MOVE_ALLOWED_PREFIXES = {
    "/move/v2/environments",
    "/move/v2/plans",
    "/move/v2/workloads",
}

_PE_ALLOWED_PARAM_KEYS = {
    "acknowledged",
    "count",
    "endTimeInUsecs",
    "include_completed",
    "include_vm_disk_config",
    "include_vm_nic_config",
    "intervalInSecs",
    "metrics",
    "page",
    "resolved",
    "search_string",
    "startTimeInUsecs",
}

_PC_ALLOWED_PARAM_KEYS = {
    "$filter",
    "$limit",
    "$page",
    "acknowledged",
    "count",
    "page",
    "resolved",
    "severity",
}

_MOVE_ALLOWED_PARAM_KEYS = {
    "planId",
    "status",
    "type",
}

_CURRENT_TOOL: ContextVar[str | None] = ContextVar("current_tool", default=None)


class _ToolLimiter:
    def __init__(self, policy: ToolSecurityPolicy) -> None:
        self._policy = policy
        self._semaphore = threading.BoundedSemaphore(policy.concurrency_limit)
        self._rate_lock = threading.Lock()
        self._timestamps: deque[float] = deque()

    def enforce_rate_limit(self, tool_name: str) -> None:
        now = time.monotonic()
        with self._rate_lock:
            while self._timestamps and now - self._timestamps[0] >= 60.0:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._policy.rate_limit_per_minute:
                raise RuntimeError(
                    f"Rate limit exceeded for tool '{tool_name}'. "
                    "Try again after a short pause."
                )
            self._timestamps.append(now)

    @contextmanager
    def acquire_slot(self, tool_name: str):
        acquired = self._semaphore.acquire(timeout=self._policy.request_timeout_seconds)
        if not acquired:
            raise RuntimeError(
                f"Concurrency limit reached for tool '{tool_name}'. "
                "Try again once active requests complete."
            )
        try:
            yield
        finally:
            self._semaphore.release()


_LIMITERS: dict[str, _ToolLimiter] = {}
_LIMITERS_LOCK = threading.Lock()


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _build_policy(raw: Mapping[str, Any], base: ToolSecurityPolicy) -> ToolSecurityPolicy:
    timeout = float(raw.get("request_timeout_seconds", base.request_timeout_seconds))
    concurrency = int(raw.get("concurrency_limit", base.concurrency_limit))
    rate = int(raw.get("rate_limit_per_minute", base.rate_limit_per_minute))

    if timeout <= 0 or timeout > 300:
        raise ValueError("request_timeout_seconds must be > 0 and <= 300.")
    if concurrency < 1 or concurrency > 100:
        raise ValueError("concurrency_limit must be between 1 and 100.")
    if rate < 1 or rate > 10000:
        raise ValueError("rate_limit_per_minute must be between 1 and 10000.")

    return ToolSecurityPolicy(
        request_timeout_seconds=timeout,
        concurrency_limit=concurrency,
        rate_limit_per_minute=rate,
    )


@lru_cache(maxsize=1)
def get_security_config() -> SecurityConfig:
    """Load and validate security configuration once per process."""
    default_policy = ToolSecurityPolicy(
        request_timeout_seconds=float(
            _env_int("NUTANIX_MCP_REQUEST_TIMEOUT_SECONDS", 30, minimum=1, maximum=300)
        ),
        concurrency_limit=_env_int("NUTANIX_MCP_TOOL_CONCURRENCY_LIMIT", 4, minimum=1, maximum=100),
        rate_limit_per_minute=_env_int("NUTANIX_MCP_RATE_LIMIT_PER_MINUTE", 120, minimum=1, maximum=10000),
    )

    overrides_raw = os.environ.get("NUTANIX_MCP_TOOL_POLICY_OVERRIDES", "").strip()
    per_tool: dict[str, ToolSecurityPolicy] = {}
    if overrides_raw:
        try:
            parsed = json.loads(overrides_raw)
        except json.JSONDecodeError as exc:
            raise ValueError("NUTANIX_MCP_TOOL_POLICY_OVERRIDES must be valid JSON.") from exc
        if not isinstance(parsed, dict):
            raise ValueError("NUTANIX_MCP_TOOL_POLICY_OVERRIDES must be a JSON object.")
        for tool_name, override in parsed.items():
            if not isinstance(tool_name, str) or not tool_name.strip():
                raise ValueError("Tool names in NUTANIX_MCP_TOOL_POLICY_OVERRIDES must be non-empty strings.")
            if not isinstance(override, dict):
                raise ValueError(
                    f"Override for tool '{tool_name}' must be a JSON object with policy fields."
                )
            per_tool[tool_name] = _build_policy(override, default_policy)

    return SecurityConfig(default_tool_policy=default_policy, per_tool_policy=per_tool)


def get_tool_policy(tool_name: str) -> ToolSecurityPolicy:
    config = get_security_config()
    return config.per_tool_policy.get(tool_name, config.default_tool_policy)


def _get_limiter(tool_name: str) -> _ToolLimiter:
    with _LIMITERS_LOCK:
        limiter = _LIMITERS.get(tool_name)
        expected_policy = get_tool_policy(tool_name)
        if limiter is None or limiter._policy != expected_policy:  # noqa: SLF001 - intentional
            limiter = _ToolLimiter(expected_policy)
            _LIMITERS[tool_name] = limiter
        return limiter


def guard_tool(tool_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Apply per-tool concurrency and rate limits, and set execution context."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            limiter = _get_limiter(tool_name)
            limiter.enforce_rate_limit(tool_name)
            token = _CURRENT_TOOL.set(tool_name)
            try:
                with limiter.acquire_slot(tool_name):
                    return func(*args, **kwargs)
            finally:
                _CURRENT_TOOL.reset(token)

        return wrapper

    return decorator


def get_active_request_timeout(default_timeout: float) -> float:
    tool_name = _CURRENT_TOOL.get()
    if not tool_name:
        return default_timeout
    return min(default_timeout, get_tool_policy(tool_name).request_timeout_seconds)


def _normalize_path(path: str) -> str:
    if not path or not path.startswith("/"):
        raise ValueError("Request path must be an absolute API path beginning with '/'.")
    if "?" in path or "#" in path:
        raise ValueError("Request path must not include query strings or fragments.")
    normalized = path.rstrip("/")
    return normalized or "/"


def _normalize_base_path(base_path: str) -> str:
    if not base_path or not base_path.startswith("/"):
        raise ValueError("API base path must begin with '/'.")
    normalized = base_path.rstrip("/")
    return normalized or "/"


def _path_allowed(normalized_path: str, allowed_prefixes: set[str]) -> bool:
    for prefix in allowed_prefixes:
        if normalized_path == prefix or normalized_path.startswith(prefix + "/"):
            return True
    return False


def _extract_param_keys(params: Any) -> set[str]:
    if params is None:
        return set()
    if isinstance(params, Mapping):
        return {str(key) for key in params.keys()}

    keys: set[str] = set()
    if isinstance(params, Iterable):
        for item in params:
            if isinstance(item, tuple) and len(item) >= 1:
                keys.add(str(item[0]))
            else:
                raise ValueError("Request params must be a mapping or sequence of key/value tuples.")
        return keys

    raise ValueError("Request params must be a mapping or sequence of key/value tuples.")


def _enforce_param_policy(path: str, params: Any, allowed_keys: set[str]) -> None:
    provided = _extract_param_keys(params)
    unknown = provided - allowed_keys
    if unknown:
        unknown_keys = ", ".join(sorted(unknown))
        raise ValueError(f"Endpoint '{path}' does not allow query parameter(s): {unknown_keys}.")


def enforce_pe_request_policy(path: str, params: Any, base_path: str) -> None:
    """Enforce Prism Element endpoint and query parameter policy."""
    normalized_base = _normalize_base_path(base_path)
    if normalized_base not in _PE_ALLOWED_BASE_PATHS:
        raise ValueError(f"PE base path '{normalized_base}' is not allowed by security policy.")

    normalized_path = _normalize_path(path)
    allowed_prefixes = _PE_ALLOWED_PREFIXES_BY_BASE_PATH[normalized_base]
    if not _path_allowed(normalized_path, allowed_prefixes):
        raise ValueError(f"PE endpoint '{normalized_path}' is not allowed by security policy.")

    _enforce_param_policy(normalized_path, params, _PE_ALLOWED_PARAM_KEYS)


def enforce_pc_request_policy(path: str, params: Any) -> None:
    """Enforce Prism Central endpoint and query parameter policy."""
    normalized_path = _normalize_path(path)
    if not _path_allowed(normalized_path, _PC_ALLOWED_PREFIXES):
        raise ValueError(f"PC endpoint '{normalized_path}' is not allowed by security policy.")

    _enforce_param_policy(normalized_path, params, _PC_ALLOWED_PARAM_KEYS)


def enforce_move_request_policy(path: str, params: Any) -> None:
    """Enforce Nutanix Move endpoint and query parameter policy."""
    normalized_path = _normalize_path(path)
    if not _path_allowed(normalized_path, _MOVE_ALLOWED_PREFIXES):
        raise ValueError(f"Move endpoint '{normalized_path}' is not allowed by security policy.")

    _enforce_param_policy(normalized_path, params, _MOVE_ALLOWED_PARAM_KEYS)

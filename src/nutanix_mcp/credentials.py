"""OS Keyring credential storage for Nutanix MCP.

Credentials are stored in the OS-native secure vault:
  - Windows: Credential Manager
  - macOS: Keychain
  - Linux: Secret Service (libsecret) with keyrings.alt as headless fallback

Service name: "nutanix-mcp"
Key format:   "<type>.<name>.<field>"

Types:
  pe   — Prism Element cluster credentials
  pc   — Prism Central credentials
  move — Nutanix Move appliance credentials

Special name "default" stores the global PE fallback (used when no per-cluster
entry exists for that cluster).

Lookup chain (per credential lookup):
    1. Named keyring entry  (e.g. pe.CLUSTER-2.username)
    2. pe.default.*         (global PE fallback, PE only)
"""

try:
    import keyring
    from keyring.errors import NoKeyringError
except ImportError as exc:
    raise ImportError(
        "The 'keyring' package is required. Install it with: pip install keyring"
    ) from exc

_SERVICE = "nutanix-mcp"


def _get(key: str):
    """Return a keyring value or None, silently falling back on headless systems."""
    try:
        return keyring.get_password(_SERVICE, key) or None
    except Exception:
        return None


def _set(key: str, value: str):
    """Store a value in the keyring."""
    keyring.set_password(_SERVICE, key, value)


# ---------------------------------------------------------------------------
# Prism Element
# ---------------------------------------------------------------------------

def get_pe_credentials(cluster_name: str) -> dict:
    """Return PE credentials for cluster_name.

    Returns a dict with keys: username, password, verify_ssl (bool).
    """
    name = (cluster_name or "").strip()

    username = _get(f"pe.{name}.username") or _get("pe.default.username") or ""
    password = _get(f"pe.{name}.password") or _get("pe.default.password") or ""
    verify_ssl_str = _get(f"pe.{name}.verify_ssl") or _get("pe.default.verify_ssl") or "false"

    username = username.strip()
    if not username or not password:
        raise EnvironmentError(
            f"No PE credentials found for cluster '{name}'. "
            "Run 'nutanix-mcp configure' to store credentials in the OS keyring."
        )
    if any(ord(ch) < 32 for ch in username):
        raise EnvironmentError(f"Stored PE username for cluster '{name}' contains invalid control characters.")

    return {
        "username": username,
        "password": password,
        "verify_ssl": verify_ssl_str.lower() == "true",
    }


def store_pe_credentials(cluster_name: str, username: str, password: str, verify_ssl: bool):
    """Store PE credentials for cluster_name (or 'default' for the global fallback)."""
    name = cluster_name or "default"
    cleaned_username = (username or "").strip()
    if not cleaned_username or not password:
        raise ValueError("PE username and password are required for keyring storage.")
    if any(ord(ch) < 32 for ch in cleaned_username):
        raise ValueError("PE username cannot contain control characters.")

    _set(f"pe.{name}.username", cleaned_username)
    _set(f"pe.{name}.password", password)
    _set(f"pe.{name}.verify_ssl", "true" if verify_ssl else "false")


# ---------------------------------------------------------------------------
# Prism Central
# ---------------------------------------------------------------------------

def get_pc_credentials(pc_name: str) -> dict:
    """Return PC credentials for pc_name.

    Returns a dict with keys: api_key (may be empty), username, password,
    verify_ssl (bool).  api_key takes precedence over username/password.
    """
    name = (pc_name or "").strip()

    api_key = (_get(f"pc.{name}.api_key") or "").strip()
    username = (_get(f"pc.{name}.username") or "").strip()
    password = _get(f"pc.{name}.password") or ""
    verify_ssl_str = _get(f"pc.{name}.verify_ssl") or _get("pe.default.verify_ssl") or "false"

    if not api_key and not username:
        raise EnvironmentError(
            f"No PC credentials found for '{name}'. "
            "Run 'nutanix-mcp configure' to store credentials in the OS keyring."
        )
    if username and not password:
        raise EnvironmentError(
            f"Stored PC username for '{name}' is missing a password in keyring."
        )
    if username and any(ord(ch) < 32 for ch in username):
        raise EnvironmentError(f"Stored PC username for '{name}' contains invalid control characters.")

    return {
        "api_key": api_key,
        "username": username,
        "password": password,
        "verify_ssl": verify_ssl_str.lower() == "true",
    }


def store_pc_credentials(pc_name: str, api_key: str = "", username: str = "", password: str = "", verify_ssl: bool = False):
    """Store PC credentials for pc_name."""
    name = pc_name or "default"
    cleaned_api_key = (api_key or "").strip()
    cleaned_username = (username or "").strip()
    cleaned_password = password or ""

    if not cleaned_api_key and not cleaned_username:
        raise ValueError("Store either a PC API key or a PC username/password pair.")
    if cleaned_username and not cleaned_password:
        raise ValueError("PC password is required when storing a PC username.")
    if cleaned_username and any(ord(ch) < 32 for ch in cleaned_username):
        raise ValueError("PC username cannot contain control characters.")

    if cleaned_api_key:
        _set(f"pc.{name}.api_key", cleaned_api_key)
    if cleaned_username:
        _set(f"pc.{name}.username", cleaned_username)
    if cleaned_password:
        _set(f"pc.{name}.password", cleaned_password)
    _set(f"pc.{name}.verify_ssl", "true" if verify_ssl else "false")


# ---------------------------------------------------------------------------
# Nutanix Move
# ---------------------------------------------------------------------------

def get_move_credentials(move_name: str) -> dict:
    """Return Move appliance credentials for move_name.

    Returns a dict with keys: username, password, verify_ssl (bool).
    """
    name = (move_name or "").strip()

    username = (_get(f"move.{name}.username") or "").strip()
    password = _get(f"move.{name}.password") or ""
    verify_ssl_str = _get(f"move.{name}.verify_ssl") or _get("pe.default.verify_ssl") or "false"

    if not username or not password:
        raise EnvironmentError(
            f"No Move credentials found for '{name}'. "
            "Run 'nutanix-mcp configure' to store credentials in the OS keyring."
        )
    if any(ord(ch) < 32 for ch in username):
        raise EnvironmentError(f"Stored Move username for '{name}' contains invalid control characters.")

    return {
        "username": username,
        "password": password,
        "verify_ssl": verify_ssl_str.lower() == "true",
    }


def store_move_credentials(move_name: str, username: str, password: str, verify_ssl: bool = False):
    """Store Move appliance credentials for move_name."""
    name = move_name or "default"
    cleaned_username = (username or "").strip()
    if not cleaned_username or not password:
        raise ValueError("Move username and password are required for keyring storage.")
    if any(ord(ch) < 32 for ch in cleaned_username):
        raise ValueError("Move username cannot contain control characters.")

    _set(f"move.{name}.username", cleaned_username)
    _set(f"move.{name}.password", password)
    _set(f"move.{name}.verify_ssl", "true" if verify_ssl else "false")

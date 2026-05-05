"""Nutanix MCP — CLI entry point.

Usage:
  nutanix-mcp              Start the MCP server (stdio transport)
  nutanix-mcp configure    Run the interactive setup wizard
"""

import getpass
import importlib
import json
import os
import shutil
import sys

MIN_PYTHON = (3, 10)
_SERVICE = "nutanix-mcp"
_SERVER_NAME = "nutanix-mcp"


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _ok(msg):   print(f"  [OK]  {msg}")
def _info(msg): print(f"        {msg}")
def _warn(msg): print(f"  [!]   {msg}")
def _fail(msg): print(f"\n  [ERR] {msg}"); sys.exit(1)


# ---------------------------------------------------------------------------
# Wizard steps
# ---------------------------------------------------------------------------

def _check_python():
    if sys.version_info < MIN_PYTHON:
        _fail(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required. "
            f"You are running {sys.version.split()[0]}."
        )
    _ok(f"Python {sys.version.split()[0]}")


def _install_dependencies():
    _info("Verifying dependencies...")
    required = [
        ("mcp", "mcp[cli]>=1.3.0"),
        ("requests", "requests>=2.31.0"),
        ("urllib3", "urllib3>=2.0.0"),
        ("yaml", "pyyaml>=6.0.0"),
        ("keyring", "keyring>=24.0.0"),
        ("keyrings.alt", "keyrings.alt>=4.0.0"),
    ]
    missing: list[str] = []
    for module_name, package_name in required:
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError:
            missing.append(package_name)
    if missing:
        missing_csv = ", ".join(missing)
        _fail(
            "Missing runtime dependencies: "
            f"{missing_csv}\n"
            "Reinstall with one of:\n"
            "  uv tool install --reinstall nutanix-mcp\n"
            "  pip install -U " + missing_csv
        )
    _ok("Dependencies available")


def _configure_credentials():
    """Store PE, PC, and Move credentials in the OS keyring."""
    import keyring

    print("\n  -- Credentials (stored securely in OS keyring) --")
    print("  Press Enter at any prompt to skip (existing values are preserved).\n")

    # Global PE default
    print("  Prism Element default credentials (used for all clusters unless overridden):")
    pe_user = input("    PE username [Enter to skip]: ").strip()
    if pe_user:
        pe_pass = getpass.getpass("    PE password: ")
        ssl_in = input("    Verify SSL certificate? (yes/no) [no]: ").strip().lower()
        verify = "true" if ssl_in == "yes" else "false"
        keyring.set_password(_SERVICE, "pe.default.username", pe_user)
        keyring.set_password(_SERVICE, "pe.default.password", pe_pass)
        keyring.set_password(_SERVICE, "pe.default.verify_ssl", verify)
        _ok("Default PE credentials stored")

    # Per-cluster PE overrides
    print("\n  Per-cluster PE credential overrides (leave blank to use the default above):")
    import yaml
    inventory = _load_inventory()
    for cluster in inventory.get("clusters", []):
        name = cluster["name"]
        override = input(f"    Override credentials for cluster '{name}'? (yes/no) [no]: ").strip().lower()
        if override == "yes":
            u = input(f"      PE username for {name}: ").strip()
            p = getpass.getpass(f"      PE password for {name}: ")
            if u:
                keyring.set_password(_SERVICE, f"pe.{name}.username", u)
                keyring.set_password(_SERVICE, f"pe.{name}.password", p)
                _ok(f"Credentials stored for cluster '{name}'")

    # PC credentials
    print("\n  Prism Central credentials (one entry per PC instance):")
    for pc in inventory.get("prism_central", []):
        name = pc["name"]
        print(f"\n    PC instance: {name}")
        print("    Option 1: API key (recommended).  Option 2: username + password.")
        api_key = input("      API key [Enter to use username/password instead]: ").strip()
        if api_key:
            ssl_in = input("      Verify SSL? (yes/no) [no]: ").strip().lower()
            verify = "true" if ssl_in == "yes" else "false"
            keyring.set_password(_SERVICE, f"pc.{name}.api_key", api_key)
            keyring.set_password(_SERVICE, f"pc.{name}.verify_ssl", verify)
            _ok(f"API key stored for PC '{name}'")
        else:
            u = input("      PC username [Enter to skip]: ").strip()
            if u:
                p = getpass.getpass("      PC password: ")
                ssl_in = input("      Verify SSL? (yes/no) [no]: ").strip().lower()
                verify = "true" if ssl_in == "yes" else "false"
                keyring.set_password(_SERVICE, f"pc.{name}.username", u)
                keyring.set_password(_SERVICE, f"pc.{name}.password", p)
                keyring.set_password(_SERVICE, f"pc.{name}.verify_ssl", verify)
                _ok(f"Credentials stored for PC '{name}'")

    # Move credentials
    for move in inventory.get("move_instances", []):
        name = move["name"]
        print(f"\n  Move appliance: {name}")
        u = input(f"    Move username [Enter to skip]: ").strip()
        if u:
            p = getpass.getpass("    Move password: ")
            ssl_in = input("    Verify SSL? (yes/no) [no]: ").strip().lower()
            verify = "true" if ssl_in == "yes" else "false"
            keyring.set_password(_SERVICE, f"move.{name}.username", u)
            keyring.set_password(_SERVICE, f"move.{name}.password", p)
            keyring.set_password(_SERVICE, f"move.{name}.verify_ssl", verify)
            _ok(f"Credentials stored for Move appliance '{name}'")


def _load_inventory() -> dict:
    path = _inventory_path()
    if path and os.path.exists(path):
        import yaml
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _inventory_path() -> str:
    return os.path.join(os.getcwd(), "inventory.yaml")


def _is_sample(entry):
    return entry.get("name", "").upper().startswith("SAMPLE-")


def _configure_pe_inventory():
    import yaml
    path = _inventory_path()
    data = _load_inventory()
    real = [c for c in data.get("clusters", []) if not _is_sample(c)]

    if real:
        print(f"\n  inventory.yaml already has {len(real)} cluster(s):")
        for c in real: print(f"    - {c['name']}  ({c['pe_host']})")
        print("  Enter additional clusters below, or press Enter to finish.")
        clusters = list(real)
    else:
        print("\n  Register your Prism Element cluster(s).")
        print("  Leave name blank to finish.\n")
        clusters = []

    while True:
        name = input("    Cluster name [blank to finish]: ").strip()
        if not name: break
        if any(c["name"].lower() == name.lower() for c in clusters):
            _warn(f"'{name}' already exists — skipping."); continue
        host = input(f"    PE IP / FQDN for '{name}' [blank to cancel]: ").strip()
        if not host: break
        clusters.append({"name": name, "pe_host": host})
        _ok(f"Added cluster '{name}' ({host})")

    if not clusters:
        _warn("No clusters added — inventory not updated.")
        return

    data["clusters"] = clusters
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    _ok(f"inventory.yaml written — {len(clusters)} cluster(s)")


def _configure_pc_inventory():
    import yaml
    path = _inventory_path()
    data = _load_inventory()
    real = [c for c in data.get("prism_central", []) if not _is_sample(c)]

    if real:
        print(f"\n  inventory.yaml already has {len(real)} Prism Central instance(s):")
        for c in real: print(f"    - {c['name']}  ({c['pc_host']})")
        print("  Enter additional instances below, or press Enter to finish.")
        instances = list(real)
    else:
        print("\n  Register your Prism Central instance(s).")
        print("  Leave name blank to finish.\n")
        instances = []

    while True:
        name = input("    PC name [blank to finish]: ").strip()
        if not name: break
        if any(c["name"].lower() == name.lower() for c in instances):
            _warn(f"'{name}' already exists — skipping."); continue
        host = input(f"    PC IP / FQDN for '{name}' [blank to cancel]: ").strip()
        if not host: break
        instances.append({"name": name, "pc_host": host})
        _ok(f"Added PC '{name}' ({host})")

    if instances:
        data["prism_central"] = instances
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        _ok(f"inventory.yaml updated — {len(instances)} PC instance(s)")


def _configure_move_inventory():
    import yaml
    path = _inventory_path()
    data = _load_inventory()
    real = [c for c in data.get("move_instances", []) if not _is_sample(c)]

    if real:
        print(f"\n  inventory.yaml already has {len(real)} Move appliance(s):")
        for c in real: print(f"    - {c['name']}  ({c['move_host']})")
        print("  Enter additional instances below, or press Enter to finish.")
        instances = list(real)
    else:
        print("\n  Register your Nutanix Move appliance(s) (optional — press Enter to skip).")
        instances = []

    while True:
        name = input("    Move appliance name [blank to finish]: ").strip()
        if not name: break
        if any(c["name"].lower() == name.lower() for c in instances):
            _warn(f"'{name}' already exists — skipping."); continue
        host = input(f"    Move IP / FQDN for '{name}' [blank to cancel]: ").strip()
        if not host: break
        instances.append({"name": name, "move_host": host})
        _ok(f"Added Move appliance '{name}' ({host})")

    if instances:
        data["move_instances"] = instances
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        _ok(f"inventory.yaml updated — {len(instances)} Move appliance(s)")


def _build_server_config(inventory_value: str, *, with_tools: bool = False) -> dict:
    server = {
        "type": "stdio",
        "command": "nutanix-mcp",
        "env": {
            "NUTANIX_MCP_INVENTORY": inventory_value,
        },
    }
    if with_tools:
        server["args"] = []
        server["tools"] = ["*"]
    return server


def _load_json_object(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            parsed = json.load(f)
    except OSError as exc:
        _fail(f"Unable to read existing config '{path}': {exc}")
    except json.JSONDecodeError as exc:
        _fail(
            f"Existing config is not valid JSON: {path}\n"
            f"Please fix it manually before running configure again ({exc.msg})."
        )
    if not isinstance(parsed, dict):
        _fail(f"Existing config root must be a JSON object: {path}")
    return parsed


def _get_servers_map(document: dict, key: str) -> dict:
    maybe_servers = document.get(key)
    if maybe_servers is None:
        return {}
    if not isinstance(maybe_servers, dict):
        _fail(f"Config key '{key}' must be a JSON object.")
    return dict(maybe_servers)


def _write_json_with_backup(path: str, payload: dict):
    if os.path.exists(path):
        backup_path = f"{path}.bak"
        shutil.copy2(path, backup_path)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)


def _create_vscode_mcp_json():
    """Write .vscode/mcp.json — server config only, no credentials."""
    vscode_dir = os.path.join(os.getcwd(), ".vscode")
    mcp_path = os.path.join(vscode_dir, "mcp.json")

    document = _load_json_object(mcp_path)

    # Preserve any existing non-nutanix-mcp servers
    existing_servers = _get_servers_map(document, "servers")
    existing_servers.pop("nutanix-prism", None)  # remove old server key if present
    existing_servers.pop(_SERVER_NAME, None)

    existing_servers[_SERVER_NAME] = _build_server_config("${workspaceFolder}/inventory.yaml")
    document["servers"] = existing_servers

    os.makedirs(vscode_dir, exist_ok=True)
    _write_json_with_backup(mcp_path, document)
    _ok(".vscode/mcp.json written (no credentials stored)")


def _create_copilot_cli_mcp_json():
    """Write ~/.copilot/mcp-config.json (or $COPILOT_HOME) with MCP server config."""
    copilot_home = os.environ.get("COPILOT_HOME") or os.path.join(os.path.expanduser("~"), ".copilot")
    mcp_path = os.path.join(copilot_home, "mcp-config.json")
    inventory_path = os.path.abspath(_inventory_path())

    document = _load_json_object(mcp_path)
    existing_servers = _get_servers_map(document, "mcpServers")
    # Preserve legacy 'servers' key content if users previously stored MCP entries there.
    existing_servers.update(_get_servers_map(document, "servers"))
    existing_servers[_SERVER_NAME] = _build_server_config(inventory_path, with_tools=True)
    document.pop("servers", None)
    document["mcpServers"] = existing_servers

    os.makedirs(copilot_home, exist_ok=True)
    _write_json_with_backup(mcp_path, document)
    _ok(f"Copilot CLI MCP config written: {mcp_path}")


def _select_config_targets() -> tuple[bool, bool]:
    print("\n  Choose config target(s):")
    print("    1) VS Code (.vscode/mcp.json)")
    print("    2) GitHub Copilot CLI (~/.copilot/mcp-config.json)")
    print("    3) Both")
    while True:
        raw = input("    Target [1/2/3] [3]: ").strip().lower()
        if raw in ("", "3", "both", "all"):
            return True, True
        if raw in ("1", "vscode", "vs code"):
            return True, False
        if raw in ("2", "copilot-cli", "copilot", "cli"):
            return False, True
        _warn("Please enter 1, 2, or 3.")


# ---------------------------------------------------------------------------
# Wizard entry point
# ---------------------------------------------------------------------------

def configure():
    """Interactive setup wizard — called by 'nutanix-mcp configure'."""
    print("\nNutanix MCP — Setup Wizard\n" + "-" * 40)
    _check_python()
    _install_dependencies()
    _configure_pe_inventory()
    _configure_pc_inventory()
    _configure_move_inventory()
    _configure_credentials()
    write_vscode, write_copilot_cli = _select_config_targets()
    if write_vscode:
        _create_vscode_mcp_json()
    if write_copilot_cli:
        _create_copilot_cli_mcp_json()
    print("\n" + "-" * 40)
    print("  Setup complete!\n")
    if write_vscode:
        print("  VS Code:")
        print("    1. Open this folder in VS Code")
        print("    2. Open Copilot Chat → Agent mode")
    if write_copilot_cli:
        print("  GitHub Copilot CLI:")
        print("    1. Start Copilot CLI in this folder")
        print("    2. Run /mcp show to confirm 'nutanix-mcp' is available")
    print("  Ask about your Nutanix environment\n")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Entry point for the 'nutanix-mcp' command.

    Without arguments: start the MCP server.
    With 'configure':  run the interactive setup wizard.
    """
    args = sys.argv[1:]

    if args and args[0] == "configure":
        configure()
        return

    if args and args[0] in ("-h", "--help"):
        print("Usage: nutanix-mcp [configure]")
        print()
        print("  (no args)    Start the Nutanix MCP server (stdio transport)")
        print("  configure    Run the interactive setup wizard")
        return

    # Start the MCP server — import here so the wizard doesn't pay the import cost
    import nutanix_mcp.tools.inventory       # noqa: F401
    import nutanix_mcp.tools.pe_cluster      # noqa: F401
    import nutanix_mcp.tools.pe_hosts        # noqa: F401
    import nutanix_mcp.tools.pe_cvms         # noqa: F401
    import nutanix_mcp.tools.pe_vms          # noqa: F401
    import nutanix_mcp.tools.pe_storage      # noqa: F401
    import nutanix_mcp.tools.pe_networking   # noqa: F401
    import nutanix_mcp.tools.pe_images       # noqa: F401
    import nutanix_mcp.tools.pe_alerts       # noqa: F401
    import nutanix_mcp.tools.pe_ops          # noqa: F401
    import nutanix_mcp.tools.pe_stats        # noqa: F401
    import nutanix_mcp.tools.pc_clusters     # noqa: F401
    import nutanix_mcp.tools.pc_vms          # noqa: F401
    import nutanix_mcp.tools.pc_hosts        # noqa: F401
    import nutanix_mcp.tools.pc_networking   # noqa: F401
    import nutanix_mcp.tools.pc_images       # noqa: F401
    import nutanix_mcp.tools.pc_storage      # noqa: F401
    import nutanix_mcp.tools.pc_alerts       # noqa: F401
    import nutanix_mcp.tools.pc_tasks        # noqa: F401
    import nutanix_mcp.tools.pc_categories   # noqa: F401
    import nutanix_mcp.tools.move_environments  # noqa: F401
    import nutanix_mcp.tools.move_plans         # noqa: F401
    import nutanix_mcp.tools.move_vms           # noqa: F401

    from nutanix_mcp.app import mcp
    mcp.run(transport="stdio")

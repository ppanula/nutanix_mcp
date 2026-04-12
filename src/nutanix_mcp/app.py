"""Shared FastMCP application instance.

Import this module wherever @mcp.tool() decorators are needed.
"""

import logging

from mcp.server.fastmcp import FastMCP
from nutanix_mcp.security import get_security_config, guard_tool

logging.getLogger("mcp").setLevel(logging.WARNING)

# Validate security configuration once at startup so misconfiguration fails fast.
get_security_config()

mcp = FastMCP(
    "Nutanix MCP",
    instructions=(
        "Provides read-only access to Nutanix infrastructure: "
        "Prism Element (PE) clusters via the v2.0 REST API, "
        "Prism Central (PC) via the v4.0 REST API, "
        "and Nutanix Move migration appliances via the v2 REST API. "
        "Call list_inventory first to see available PC instances, PE clusters, and Move appliances, "
        "then pass pc_name to PC tools (prefixed pc_), cluster_name to PE tools, "
        "or move_name to Move tools (prefixed move_). "
        "If only one entry is defined for a type, it is selected automatically. "
        "PC tool responses use extId (not uuid) as the unique identifier for each entity. "
        "Use extId values returned by list_* tools as input for get_* tools. "
        "PC tools operate across all clusters managed by that Prism Central instance."
    ),
)

_raw_tool = mcp.tool


def _secured_tool(*tool_args, **tool_kwargs):
    """Wrap each registered tool with runtime guardrails."""
    base_decorator = _raw_tool(*tool_args, **tool_kwargs)

    def decorator(func):
        return base_decorator(guard_tool(func.__name__)(func))

    return decorator


mcp.tool = _secured_tool

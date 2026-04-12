"""Nutanix API HTTP clients.

pe_get    — Prism Element v2.0 REST API (per-cluster, GET)
pc_v4_get — Prism Central v4.0 REST API (GET, OData query params)
move_get  — Nutanix Move v2 REST API (GET)

All three functions accept per-call credential keyword arguments so that each
tool can pass the credentials resolved from the OS keyring for that specific
cluster or appliance.
"""

import requests
import urllib3

from nutanix_mcp.security import (
    enforce_move_request_policy,
    enforce_pc_request_policy,
    enforce_pe_request_policy,
    get_active_request_timeout,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PE_BASE_PATH = "/PrismGateway/services/rest/v2.0"


def pe_get(path, params=None, *, host, username, password, verify_ssl=False, base_path=None):
    """Issue an authenticated GET request to Prism Element and return parsed JSON.

    host, username, password, verify_ssl — supplied by resolve_cluster().
    base_path overrides the default v2.0 base when a different API version is
    needed, e.g. base_path='/api/nutanix/v0.8' for the ergon task service.
    """
    effective_base = base_path if base_path is not None else _PE_BASE_PATH
    enforce_pe_request_policy(path, params, effective_base)
    url = f"https://{host}:9440{effective_base}{path}"
    try:
        response = requests.get(
            url,
            auth=(username, password),
            params=params,
            verify=verify_ssl,
            timeout=get_active_request_timeout(30),
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as exc:
        raise RuntimeError(
            f"SSL error connecting to {host}. Pass verify_ssl=True or ensure the "
            "certificate is trusted."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Cannot connect to {host}:9440. Verify the host is reachable."
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"HTTP {status} from Nutanix PE API.") from exc


def pc_v4_get(path, params=None, *, host, api_key="", username="", password="", verify_ssl=False):
    """Issue an authenticated GET to a Prism Central endpoint and return parsed JSON.

    path should be the full sub-path including namespace and version, e.g.
    '/api/vmm/v4.0/ahv/config/vms'.  OData query params ($page, $limit, $filter
    etc.) are passed via the params dict.

    Authentication priority: api_key (X-Ntnx-Api-Key header) takes precedence
    over basic auth if provided.
    host, api_key/username/password, verify_ssl — supplied by resolve_pc_instance().
    """
    if not api_key and not username:
        raise EnvironmentError(
            f"No Prism Central credentials found for host '{host}'. "
            "Run 'nutanix-mcp configure' to store credentials in the OS keyring."
        )
    enforce_pc_request_policy(path, params)
    url = f"https://{host}:9440{path}"
    if api_key:
        auth = None
        headers = {"Accept": "application/json", "X-Ntnx-Api-Key": api_key}
    else:
        auth = (username, password)
        headers = {"Accept": "application/json"}
    try:
        response = requests.get(
            url,
            auth=auth,
            params=params,
            verify=verify_ssl,
            timeout=get_active_request_timeout(30),
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as exc:
        raise RuntimeError(
            f"SSL error connecting to {host}. Pass verify_ssl=True or ensure the "
            "certificate is trusted."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(f"Cannot connect to {host}:9440. Verify the host is reachable.") from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"HTTP {status} from Nutanix PC API.") from exc


def move_get(path, params=None, *, host, username, password, verify_ssl=False):
    """Issue an authenticated GET request to a Nutanix Move appliance and return parsed JSON.

    Move runs on port 443 (not 9440).
    host, username, password, verify_ssl — supplied by resolve_move_instance().
    """
    enforce_move_request_policy(path, params)
    url = f"https://{host}{path}"
    try:
        response = requests.get(
            url,
            auth=(username, password),
            params=params,
            verify=verify_ssl,
            timeout=get_active_request_timeout(30),
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.SSLError as exc:
        raise RuntimeError(
            f"SSL error connecting to Move appliance at {host}."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Cannot connect to Move appliance at {host}. Verify the host is reachable."
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise RuntimeError(f"HTTP {status} from Nutanix Move API.") from exc

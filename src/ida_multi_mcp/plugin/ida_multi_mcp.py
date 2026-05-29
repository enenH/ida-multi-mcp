"""IDA Pro plugin for ida-multi-mcp.

Replaces the original ida_mcp.py plugin loader. Does everything the original
does (starts MCP HTTP server with all 71+ tools) PLUS auto-registers with
the central instance registry for multi-instance support.

The ida_mcp package is bundled with ida-multi-mcp and provides all IDA tools.
"""

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import idaapi
import ida_kernwin

# Import registration functions (add parent to path for ida_multi_mcp imports)
_pkg_dir = str(Path(__file__).parent.parent.parent)
if _pkg_dir not in sys.path:
    sys.path.append(_pkg_dir)

from ida_multi_mcp.plugin.registration import (
    register_instance,
    unregister_instance,
    update_heartbeat,
    get_binary_metadata,
)

DEFAULT_BROKER_URL = "http://127.0.0.1:13337"
AUTO_START_BROKER = os.environ.get("IDA_MULTI_MCP_AUTO_START_BROKER", "1").lower() not in {
    "0",
    "false",
    "no",
    "off",
}
BROKER_STARTUP_TIMEOUT = 12.0
_broker_start_lock = threading.Lock()
_broker_process: subprocess.Popen | None = None


def _is_gui_runtime() -> bool:
    """Return True when running inside the interactive IDA GUI."""
    checker = getattr(ida_kernwin, "is_idaq", None)
    if checker is None:
        return True
    try:
        return bool(checker())
    except Exception:
        return True


def _load_ida_mcp():
    """Load the ida_mcp package (bundled with ida-multi-mcp).

    Returns:
        Tuple of (MCP_SERVER, IdaMcpHttpRequestHandler, init_caches)

    Raises:
        ImportError: If ida_mcp package is not available
    """
    from ida_multi_mcp.ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
    return MCP_SERVER, IdaMcpHttpRequestHandler, init_caches


def _broker_host_port(broker_url: str) -> tuple[str, int]:
    parsed = urlparse(broker_url)
    host = parsed.hostname or "127.0.0.1"
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80
    return host, port


def _is_local_host(host: str) -> bool:
    return host.lower() in {"127.0.0.1", "localhost", "::1"}


def _is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _find_external_python() -> str | None:
    env_python = os.environ.get("IDA_MULTI_MCP_PYTHON") or os.environ.get("IDA_MCP_PYTHON")
    if env_python and os.path.exists(env_python):
        return env_python

    exe_name = os.path.basename(sys.executable).lower()
    if exe_name.startswith("python") and os.path.exists(sys.executable):
        return sys.executable

    candidates: list[Path] = []
    package_root = Path(__file__).resolve().parents[2]
    for parent in package_root.parents:
        candidates.extend([parent / "python.exe", parent / "pythonw.exe"])
        candidates.extend([parent / "bin" / "python3", parent / "bin" / "python"])

    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        if local_appdata:
            candidates.extend(
                Path(local_appdata).glob("Programs/Python/Python*/python.exe")
            )

    for candidate in candidates:
        try:
            if candidate.exists():
                return str(candidate)
        except OSError:
            continue
    return None


def _broker_log_paths() -> tuple[str, str]:
    base_dir = (
        os.environ.get("IDA_MULTI_MCP_LOG_DIR")
        or os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ida-multi-mcp", "logs")
    )
    os.makedirs(base_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return (
        os.path.join(base_dir, f"ida-multi-mcp-broker-{stamp}.out.log"),
        os.path.join(base_dir, f"ida-multi-mcp-broker-{stamp}.err.log"),
    )


def _ensure_broker_running(broker_url: str | None = None, silent: bool = False) -> bool:
    """Start the localhost HTTP broker if it is not already listening."""
    if not AUTO_START_BROKER:
        return False

    broker_url = broker_url or os.environ.get("IDA_MULTI_MCP_BROKER_URL", DEFAULT_BROKER_URL)
    try:
        host, port = _broker_host_port(broker_url)
    except Exception as exc:
        if not silent:
            print(f"[ida-multi-mcp] Broker URL parse failed: {exc}")
        return False

    if not _is_local_host(host):
        return False

    if _is_port_open(host, port):
        return True

    with _broker_start_lock:
        if _is_port_open(host, port):
            return True

        python_path = _find_external_python()
        if not python_path:
            if not silent:
                print("[ida-multi-mcp] Broker is not running and no external Python was found")
            return False

        stdout_log, stderr_log = _broker_log_paths()
        stdout_file = open(stdout_log, "ab")
        stderr_file = open(stderr_log, "ab")
        args = [
            python_path,
            "-m",
            "ida_multi_mcp",
            "--broker",
            "--host",
            host,
            "--port",
            str(port),
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        child_env = os.environ.copy()
        package_parent = str(Path(__file__).resolve().parents[2])
        existing_pythonpath = child_env.get("PYTHONPATH", "")
        if package_parent not in existing_pythonpath.split(os.pathsep):
            child_env["PYTHONPATH"] = (
                package_parent
                if not existing_pythonpath
                else package_parent + os.pathsep + existing_pythonpath
            )

        try:
            global _broker_process
            _broker_process = subprocess.Popen(
                args,
                stdout=stdout_file,
                stderr=stderr_file,
                stdin=subprocess.DEVNULL,
                creationflags=creationflags,
                env=child_env,
            )
        except Exception as exc:
            if not silent:
                print(f"[ida-multi-mcp] Broker auto-start failed: {exc}")
            return False
        finally:
            stdout_file.close()
            stderr_file.close()

        if not silent:
            print(f"[ida-multi-mcp] Broker auto-started: http://{host}:{port}")
            print(f"[ida-multi-mcp] Broker log: {stderr_log}")

    deadline = time.time() + BROKER_STARTUP_TIMEOUT
    while time.time() < deadline:
        if _is_port_open(host, port):
            return True
        time.sleep(0.25)

    if not silent:
        print(f"[ida-multi-mcp] Broker did not listen on {host}:{port} after auto-start")
    return False


class IdaMultiMcpPlugin(idaapi.plugin_t):
    """IDA plugin that runs MCP server and registers with central registry.

    This plugin replaces the original ida_mcp.py loader. It:
    1. Loads the ida_mcp package (all 71+ tools and 24 resources)
    2. Starts an HTTP server on an OS-assigned port (port 0)
    3. Registers with the central instance registry (~/.ida-mcp/instances.json)
    4. Sends periodic heartbeats
    5. Unregisters on database close or plugin termination
    """

    flags = idaapi.PLUGIN_FIX  # Auto-load on startup
    comment = "Multi-instance MCP server plugin"
    help = "Runs MCP server and registers with ida-multi-mcp"
    wanted_name = "ida-multi-mcp"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self.mcp_server = None
        self.stop_event = threading.Event()
        self.heartbeat_thread = None
        self.instance_id = None
        self.server_port = None
        self.hooks_installed = False

    def init(self):
        """Plugin initialization — install hooks, start if DB already open."""
        if _is_gui_runtime():
            print("[ida-multi-mcp] Plugin loaded (PLUGIN_FIX)")
        else:
            print("[ida-multi-mcp] Plugin loaded (headless mode, server managed externally)")

        # Install hooks for database lifecycle events
        self.idb_hooks = IdbHooks(self)
        self.ui_hooks = UiHooks(self)
        self.idb_hooks.hook()
        self.ui_hooks.hook()
        self.hooks_installed = True

        # If database is already open, start immediately
        if _is_gui_runtime() and idaapi.get_input_file_path():
            self.start_server()

        return idaapi.PLUGIN_KEEP

    def start_server(self):
        """Start the MCP server with all IDA tools and register with registry."""
        if self.mcp_server and self.mcp_server._running:
            print("[ida-multi-mcp] Server already running")
            return

        print("[ida-multi-mcp] Starting MCP server...")
        _ensure_broker_running(silent=True)

        # Get binary metadata for registration
        metadata = get_binary_metadata()

        try:
            # Load the ida_mcp package (provides MCP_SERVER with 71+ tools)
            mcp_server, handler_class, init_caches = _load_ida_mcp()
        except ImportError as e:
            print(f"[ida-multi-mcp] ERROR: ida_mcp package failed to load: {e}")
            print("[ida-multi-mcp] This indicates a broken installation. Reinstall ida-multi-mcp.")
            return

        try:
            # Initialize caches (function cache, etc.)
            init_caches()
        except Exception as e:
            print(f"[ida-multi-mcp] Cache init warning: {e}")

        try:
            # Start HTTP server on port 0 (OS-assigned) — key difference from original!
            mcp_server.serve(
                host="127.0.0.1",
                port=0,
                background=True,
                request_handler=handler_class,
            )
            self.mcp_server = mcp_server

            # Get the actual port assigned by the OS
            if self.mcp_server._http_server:
                self.server_port = self.mcp_server._http_server.server_address[1]
                print(f"[ida-multi-mcp] Server listening on 127.0.0.1:{self.server_port}")

                # Update download base URL to reflect the actual dynamic port
                from ida_multi_mcp.ida_mcp.rpc import set_download_base_url
                set_download_base_url(f"http://127.0.0.1:{self.server_port}")

                # Register with central instance registry
                self.instance_id = register_instance(
                    pid=os.getpid(),
                    port=self.server_port,
                    idb_path=metadata["idb_path"],
                    binary_path=metadata["binary_path"],
                    binary_name=metadata["binary_name"],
                    arch=metadata["arch"],
                    host="127.0.0.1",
                )
                print(f"[ida-multi-mcp] Registered as instance '{self.instance_id}' "
                      f"({metadata['binary_name']})")

                # Start heartbeat thread
                self.stop_event.clear()
                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop,
                    daemon=True,
                )
                self.heartbeat_thread.start()
            else:
                print("[ida-multi-mcp] Failed to get server port")

        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[ida-multi-mcp] Error: Port binding failed")
            else:
                print(f"[ida-multi-mcp] Failed to start server: {e}")
                import traceback
                traceback.print_exc()

    def _heartbeat_loop(self):
        """Send periodic heartbeats to the central registry (every 60s)."""
        while not self.stop_event.is_set():
            try:
                if self.instance_id:
                    update_heartbeat(self.instance_id)
            except Exception as e:
                print(f"[ida-multi-mcp] Heartbeat error: {e}")
            self.stop_event.wait(timeout=60.0)

    def stop_server(self):
        """Stop the MCP server and unregister from the central registry."""
        if not self.mcp_server:
            return

        print("[ida-multi-mcp] Stopping server...")

        # Stop heartbeat
        self.stop_event.set()
        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2.0)
            self.heartbeat_thread = None

        # Unregister from central registry
        if self.instance_id:
            try:
                unregister_instance(self.instance_id)
                print(f"[ida-multi-mcp] Unregistered instance '{self.instance_id}'")
            except Exception as e:
                print(f"[ida-multi-mcp] Failed to unregister: {e}")
            self.instance_id = None

        # Stop MCP HTTP server
        if self.mcp_server:
            self.mcp_server.stop()
            self.mcp_server = None

        self.server_port = None

    def run(self, arg):
        """Toggle server on/off when activated via menu or hotkey."""
        if self.mcp_server and self.mcp_server._running:
            self.stop_server()
        else:
            self.start_server()

    def term(self):
        """Plugin termination — cleanup everything."""
        print("[ida-multi-mcp] Plugin terminating")

        if self.hooks_installed:
            self.idb_hooks.unhook()
            self.ui_hooks.unhook()
            self.hooks_installed = False

        self.stop_server()


class IdbHooks(idaapi.IDB_Hooks):
    """IDB hooks for detecting database close (binary change detection)."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def closebase(self):
        """Called when database is being closed — stop server and unregister."""
        print("[ida-multi-mcp] Database closing")
        self.plugin.stop_server()
        return 0


class UiHooks(idaapi.UI_Hooks):
    """UI hooks for detecting database initialization."""

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def database_inited(self, is_new_database, idc_script):
        """Called when a new database is initialized — start server."""
        print("[ida-multi-mcp] Database initialized")
        if _is_gui_runtime():
            self.plugin.start_server()
        return 0


def PLUGIN_ENTRY():
    """IDA plugin entry point."""
    return IdaMultiMcpPlugin()

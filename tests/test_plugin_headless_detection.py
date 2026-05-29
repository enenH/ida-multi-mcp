"""Tests for GUI vs headless detection in the IDA plugin wrapper."""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _load_plugin_module(monkeypatch, *, is_idaq: bool, input_path: str = "sample.bin"):
    for name in list(sys.modules):
        if name == "ida_multi_mcp.plugin.ida_multi_mcp":
            sys.modules.pop(name, None)

    idaapi = types.ModuleType("idaapi")
    idaapi.plugin_t = type("plugin_t", (), {})
    idaapi.IDB_Hooks = type("IDB_Hooks", (), {"hook": lambda self: None, "unhook": lambda self: None})
    idaapi.UI_Hooks = type("UI_Hooks", (), {"hook": lambda self: None, "unhook": lambda self: None})
    idaapi.PLUGIN_FIX = 1
    idaapi.PLUGIN_KEEP = 2
    idaapi.get_input_file_path = lambda: input_path
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.is_idaq = lambda: is_idaq
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)

    registration = types.ModuleType("ida_multi_mcp.plugin.registration")
    registration.register_instance = MagicMock(return_value="abcd")
    registration.unregister_instance = MagicMock()
    registration.update_heartbeat = MagicMock()
    registration.get_binary_metadata = MagicMock(
        return_value={
            "idb_path": "sample.i64",
            "binary_path": "sample.bin",
            "binary_name": "sample.bin",
            "arch": "metapc-64",
        }
    )
    monkeypatch.setitem(sys.modules, "ida_multi_mcp.plugin.registration", registration)

    module = importlib.import_module("ida_multi_mcp.plugin.ida_multi_mcp")
    importlib.reload(module)
    return module


def test_plugin_init_autostarts_only_in_gui(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    rc = plugin.init()

    assert rc == module.idaapi.PLUGIN_KEEP
    plugin.start_server.assert_called_once()


def test_plugin_init_skips_autostart_in_headless(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=False)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    rc = plugin.init()

    assert rc == module.idaapi.PLUGIN_KEEP
    plugin.start_server.assert_not_called()


def test_database_inited_starts_only_in_gui(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    hooks = module.UiHooks(plugin)
    rc = hooks.database_inited(False, "")

    assert rc == 0
    plugin.start_server.assert_called_once()


def test_database_inited_skips_in_headless(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=False)
    plugin = module.IdaMultiMcpPlugin()
    plugin.start_server = MagicMock()

    hooks = module.UiHooks(plugin)
    rc = hooks.database_inited(False, "")

    assert rc == 0
    plugin.start_server.assert_not_called()


def test_broker_url_defaults_to_13337(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)

    assert module._broker_host_port("http://127.0.0.1:13337") == ("127.0.0.1", 13337)
    assert module._broker_host_port("http://localhost") == ("localhost", 80)


def test_broker_auto_start_skips_when_disabled(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    monkeypatch.setattr(module, "AUTO_START_BROKER", False)
    popen = MagicMock()
    monkeypatch.setattr(module.subprocess, "Popen", popen)

    assert module._ensure_broker_running("http://127.0.0.1:13337", silent=True) is False
    popen.assert_not_called()


def test_broker_auto_start_skips_when_port_open(monkeypatch):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    monkeypatch.setattr(module, "AUTO_START_BROKER", True)
    monkeypatch.setattr(module, "_is_port_open", lambda host, port: True)
    popen = MagicMock()
    monkeypatch.setattr(module.subprocess, "Popen", popen)

    assert module._ensure_broker_running("http://127.0.0.1:13337", silent=True) is True
    popen.assert_not_called()


def test_broker_auto_start_launches_module(monkeypatch, tmp_path):
    module = _load_plugin_module(monkeypatch, is_idaq=True)
    python = tmp_path / "python.exe"
    python.write_text("", encoding="utf-8")
    monkeypatch.setattr(module, "AUTO_START_BROKER", True)
    monkeypatch.setattr(module, "BROKER_STARTUP_TIMEOUT", 0.01)
    monkeypatch.setattr(module, "_find_external_python", lambda: str(python))
    monkeypatch.setattr(
        module,
        "_broker_log_paths",
        lambda: (str(tmp_path / "out.log"), str(tmp_path / "err.log")),
    )

    checks = iter([False, False, True])
    monkeypatch.setattr(module, "_is_port_open", lambda host, port: next(checks, True))
    popen = MagicMock()
    monkeypatch.setattr(module.subprocess, "Popen", popen)

    assert module._ensure_broker_running("http://127.0.0.1:13337", silent=True) is True
    args = popen.call_args.args[0]
    assert args[:3] == [str(python), "-m", "ida_multi_mcp"]
    assert "--broker" in args
    assert "13337" in args
    assert "PYTHONPATH" in popen.call_args.kwargs["env"]

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))


class TestArchitectureFixes(unittest.TestCase):
    def test_expired_reason_uses_reason_key(self):
        from ida_multi_mcp.registry import InstanceRegistry
        from ida_multi_mcp.router import InstanceRouter

        with tempfile.TemporaryDirectory() as td:
            registry = InstanceRegistry(os.path.join(td, "instances.json"))
            instance_id = registry.register(
                pid=111,
                port=2222,
                idb_path="/tmp/sample.i64",
                binary_name="sample.exe",
                binary_path="/tmp/sample.exe",
                arch="x64",
                host="127.0.0.1",
            )
            registry.expire_instance(instance_id, reason="process_dead")

            router = InstanceRouter(registry)
            resp = router.route_request(
                "tools/call",
                {"name": "decompile", "arguments": {"instance_id": instance_id, "addr": "0x401000"}},
            )

            self.assertIn("reason", resp)
            self.assertEqual(resp["reason"], "process_dead")

    def test_registry_recovers_from_corrupted_json(self):
        from ida_multi_mcp.registry import InstanceRegistry

        with tempfile.TemporaryDirectory() as td:
            registry_path = os.path.join(td, "instances.json")
            with open(registry_path, "w", encoding="utf-8") as f:
                f.write("{this is invalid json")

            registry = InstanceRegistry(registry_path)
            instances = registry.list_instances()

            self.assertEqual(instances, {})
            corrupt_files = [p for p in os.listdir(td) if p.startswith("instances.json.corrupt-")]
            self.assertTrue(corrupt_files)

    def test_default_registry_path_honors_env(self):
        from ida_multi_mcp.registry import InstanceRegistry, REGISTRY_PATH_ENV

        with tempfile.TemporaryDirectory() as td:
            custom = os.path.join(td, "custom-instances.json")
            old = os.environ.get(REGISTRY_PATH_ENV)
            try:
                os.environ[REGISTRY_PATH_ENV] = custom
                registry = InstanceRegistry()
                self.assertEqual(registry.registry_path, custom)
            finally:
                if old is None:
                    os.environ.pop(REGISTRY_PATH_ENV, None)
                else:
                    os.environ[REGISTRY_PATH_ENV] = old

    def test_decompile_to_file_avoids_filename_collision(self):
        from ida_multi_mcp.server import IdaMultiMcpServer

        with tempfile.TemporaryDirectory() as td:
            registry_path = os.path.join(td, "instances.json")
            out_dir = os.path.join(td, "out")
            server = IdaMultiMcpServer(registry_path=registry_path)

            def fake_route_request(_method, params):
                name = params.get("name")
                args = params.get("arguments", {})
                if name == "decompile":
                    addr = args.get("addr")
                    payload = {"name": "same_name", "code": f"// code for {addr}"}
                    return {"content": [{"text": json.dumps(payload)}]}
                raise AssertionError(f"Unexpected routed tool: {name}")

            server.router.route_request = fake_route_request

            result = server._handle_decompile_to_file(
                {
                    "addrs": ["0x401000", "0x402000"],
                    "output_dir": out_dir,
                    "mode": "single",
                    "instance_id": "abcd",
                }
            )

            self.assertEqual(result["success"], 2)
            files = sorted(result["files"])
            self.assertEqual(len(files), 2)
            self.assertNotEqual(files[0], files[1])
            self.assertTrue(files[0].endswith("0x401000.c") or files[1].endswith("0x401000.c"))
            self.assertTrue(files[0].endswith("0x402000.c") or files[1].endswith("0x402000.c"))

    def test_cmd_install_returns_error_on_missing_package(self):
        import builtins
        from ida_multi_mcp import __main__ as cli

        args = type("Args", (), {"ida_dir": None})()
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "ida_multi_mcp":
                raise ImportError("simulated missing package")
            return real_import(name, *a, **kw)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            rc = cli.cmd_install(args)

        self.assertEqual(rc, 1)

    def test_cmd_install_copies_real_loader_file(self):
        from ida_multi_mcp import __main__ as cli

        with tempfile.TemporaryDirectory() as td:
            plugins_dir = Path(td) / "plugins"
            args = type("Args", (), {"ida_dir": None})()

            with mock.patch.object(cli, "_get_ida_plugins_dir", return_value=plugins_dir), \
                 mock.patch.object(cli, "_configure_idalib_path"), \
                 mock.patch.object(cli, "install_mcp_servers"):
                rc = cli.cmd_install(args)

            loader = plugins_dir / "ida_multi_mcp.py"
            self.assertEqual(rc, 0)
            self.assertTrue(loader.exists())
            self.assertFalse(loader.is_symlink())
            self.assertGreater(loader.stat().st_size, 0)
            self.assertIn("IDA plugin loader for ida-multi-mcp", loader.read_text(encoding="utf-8"))

    def test_cmd_install_disables_legacy_ida_pro_mcp_plugins(self):
        from ida_multi_mcp import __main__ as cli

        with tempfile.TemporaryDirectory() as td:
            plugins_dir = Path(td) / "plugins"
            plugins_dir.mkdir()
            (plugins_dir / "ida_mcp.py").write_text("# old loader", encoding="utf-8")
            (plugins_dir / "ida_mcp").mkdir()
            (plugins_dir / "broker").mkdir()
            args = type("Args", (), {"ida_dir": None})()

            with mock.patch.object(cli, "_get_ida_plugins_dir", return_value=plugins_dir), \
                 mock.patch.object(cli, "_configure_idalib_path"), \
                 mock.patch.object(cli, "install_mcp_servers"):
                rc = cli.cmd_install(args)

            self.assertEqual(rc, 0)
            self.assertFalse((plugins_dir / "ida_mcp.py").exists())
            self.assertFalse((plugins_dir / "ida_mcp").exists())
            # Plain directories named "broker" are not enough to identify the
            # old install. This avoids disabling unrelated plugins.
            self.assertTrue((plugins_dir / "broker").exists())
            self.assertTrue(list(plugins_dir.glob("ida_mcp.py.disabled-*")))
            self.assertTrue(list(plugins_dir.glob("ida_mcp.disabled-*")))


if __name__ == "__main__":
    unittest.main()

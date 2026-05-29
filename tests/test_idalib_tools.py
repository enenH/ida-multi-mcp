from unittest.mock import MagicMock

from ida_multi_mcp.tools import idalib


def test_idalib_open_passes_ida_args():
    manager = MagicMock()
    manager.spawn_session.return_value = {"instance_id": "abcd"}
    idalib.set_manager(manager)

    result = idalib.idalib_open(
        {
            "input_path": "raw.bin",
            "timeout": 7,
            "unsafe": True,
            "ida_args": "-pARM",
        }
    )

    assert result == {"instance_id": "abcd"}
    manager.spawn_session.assert_called_once_with(
        "raw.bin",
        timeout=7,
        unsafe=True,
        ida_args="-pARM",
    )


def test_idalib_open_rejects_non_string_ida_args():
    manager = MagicMock()
    idalib.set_manager(manager)

    result = idalib.idalib_open({"input_path": "raw.bin", "ida_args": ["-pARM"]})

    assert "error" in result
    manager.spawn_session.assert_not_called()

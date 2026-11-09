import asyncio
import os
import sys
import pytest
from app.process_guard import ProcessGuard


@pytest.mark.asyncio
async def test_scanner_group_is_owned_and_terminated(tmp_path):
    marker = tmp_path / "started"
    code = "import time; from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('started'); time.sleep(60)"
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", code, start_new_session=os.name != "nt")
    guard = ProcessGuard(process.pid)
    try:
        for _ in range(100):
            if marker.exists():
                break
            await asyncio.sleep(0.05)
        assert marker.exists()
    finally:
        guard.close()
    await asyncio.wait_for(process.wait(), 5)
    assert process.returncode is not None  # Windows Job Object termination may report zero.

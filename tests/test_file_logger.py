import json
import os
import shutil
import sys

import pytest

from trapster.logger import FileLogger


def log_event(logger, marker):
    logger.log(
        "login",
        None,
        extra={
            "src_ip": "127.0.0.1",
            "src_port": 1,
            "dst_ip": "127.0.0.1",
            "dst_port": 21,
            "marker": marker,
        },
    )


def test_persist_keeps_log_across_restarts(tmp_path):
    logfile = str(tmp_path / "trapster.log")

    logger = FileLogger("node", logfile=logfile, persist=True)
    log_event(logger, "before-restart")
    del logger

    logger = FileLogger("node", logfile=logfile, persist=True)
    log_event(logger, "after-restart")

    with open(logfile) as f:
        content = f.read()
    assert "before-restart" in content
    assert "after-restart" in content


def test_default_starts_empty_on_each_start(tmp_path):
    logfile = str(tmp_path / "trapster.log")

    logger = FileLogger("node", logfile=logfile)
    log_event(logger, "first-run")

    logger = FileLogger("node", logfile=logfile)
    log_event(logger, "second-run")

    with open(logfile) as f:
        content = f.read()
    assert "first-run" not in content
    assert "second-run" in content


def test_writes_survive_copytruncate_rotation(tmp_path):
    logfile = str(tmp_path / "trapster.log")

    logger = FileLogger("node", logfile=logfile, persist=True)
    for i in range(500):
        log_event(logger, f"pre-rotation-{i}")

    # copytruncate-style rotation: copy aside, then truncate in place
    shutil.copyfile(logfile, logfile + ".1")
    open(logfile, "w").close()
    log_event(logger, "post-rotation")

    with open(logfile, "rb") as f:
        data = f.read()
    assert b"\x00" not in data
    assert data.count(b"\n") == 1
    assert b"post-rotation" in data
    json.loads(data.decode().strip())


@pytest.mark.skipif(sys.platform == "win32", reason="renaming an open file requires POSIX semantics")
def test_writes_follow_rename_rotation(tmp_path):
    logfile = str(tmp_path / "trapster.log")

    logger = FileLogger("node", logfile=logfile, persist=True)
    log_event(logger, "pre-rotation")
    os.replace(logfile, logfile + ".1")
    log_event(logger, "post-rotation")

    with open(logfile) as f:
        content = f.read()
    assert "post-rotation" in content
    assert "pre-rotation" not in content


@pytest.mark.skipif(sys.platform == "win32", reason="removing an open file requires POSIX semantics")
def test_writes_recreate_removed_file(tmp_path):
    logfile = str(tmp_path / "trapster.log")

    logger = FileLogger("node", logfile=logfile, persist=True)
    log_event(logger, "pre-removal")
    os.remove(logfile)
    log_event(logger, "post-removal")

    with open(logfile) as f:
        content = f.read()
    assert "post-removal" in content

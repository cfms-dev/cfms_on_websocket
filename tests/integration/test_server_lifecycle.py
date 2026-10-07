import pytest

from tests.support import server
from tests.support.config import ServerTestSettings


@pytest.fixture
def started_processes(monkeypatch):
    processes = []
    original_popen = server.subprocess.Popen

    def spawn(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(server.subprocess, "Popen", spawn)
    try:
        yield processes
    finally:
        for process in processes:
            server.stop_server(process, None)


def test_failed_log_thread_start_stops_server_and_started_reader(
    tmp_path, monkeypatch, started_processes
):
    (tmp_path / "main.py").write_text(
        "from threading import Event\nEvent().wait()\n", encoding="utf-8"
    )
    settings = ServerTestSettings(
        host="::1",
        port=1,
        use_ssl=False,
        src_dir=tmp_path,
        config_path=tmp_path / "config.toml",
    )
    threads = []
    original_start = server.threading.Thread.start

    def start_or_fail(thread):
        threads.append(thread)
        if len(threads) == 2:
            raise RuntimeError("log reader failed to start")
        original_start(thread)

    monkeypatch.setattr(server.threading.Thread, "start", start_or_fail)

    with pytest.raises(RuntimeError, match="log reader failed to start"):
        server.start_server(settings)

    assert started_processes[0].poll() is not None
    assert started_processes[0].stdout.closed
    assert started_processes[0].stderr.closed
    assert all(not thread.is_alive() for thread in threads)


def test_server_exit_before_readiness_closes_process_resources(
    tmp_path, started_processes
):
    (tmp_path / "main.py").write_text(
        "raise RuntimeError('startup failure')\n", encoding="utf-8"
    )
    settings = ServerTestSettings(
        host="::1",
        port=1,
        use_ssl=False,
        src_dir=tmp_path,
        config_path=tmp_path / "config.toml",
    )

    with pytest.raises(RuntimeError, match="Test server exited during startup"):
        server.start_server(settings)

    assert started_processes[0].poll() == 1
    assert started_processes[0].stdout.closed
    assert started_processes[0].stderr.closed

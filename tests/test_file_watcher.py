#!/usr/bin/env python3

"""Tests for file_watcher.py - CopyCompletionWatcher batch dispatch logic."""

import time
import unittest.mock as mock
from file_watcher import CopyCompletionWatcher
from watchdog.events import FileSystemEvent, FileSystemEventHandler


def _make_mock_event(src_path, is_directory=False):
    """Create a mock watchdog FileSystemEvent."""
    event = mock.MagicMock(spec=FileSystemEvent)
    event.src_path = src_path
    event.is_directory = is_directory
    return event


def _make_watcher(delay=5, max_batch=0, callback=None):
    """Create a CopyCompletionWatcher with a mock callback."""
    config = mock.MagicMock()
    config.watch_batch_delay = delay
    config.watch_max_batch = max_batch
    if callback is None:
        callback = mock.MagicMock()
    watcher = CopyCompletionWatcher(config, callback)
    return watcher, callback


class TestPendingFiles:
    def test_get_pending_count_initially_zero(self):
        """New watcher should have zero pending files."""
        watcher, _ = _make_watcher()
        assert watcher.get_pending_count() == 0

    def test_on_created_adds_to_pending(self):
        """on_created should add file to pending set."""
        watcher, _ = _make_watcher()
        event = _make_mock_event("/tmp/input/test.exe")
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=1024):
                watcher.on_created(event)
        assert watcher.get_pending_count() == 1

    def test_on_modified_resets_timer(self):
        """on_modified should update last_activity timestamp."""
        watcher, _ = _make_watcher()
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=500):
                watcher.on_created(_make_mock_event("/tmp/input/test.exe"))
        old_activity = watcher.last_activity
        time.sleep(0.05)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=800):
                watcher.on_modified(_make_mock_event("/tmp/input/test.exe"))
        assert watcher.last_activity > old_activity

    def test_on_modified_nonexistent_file_ignored(self):
        """on_modified for a file not in pending should be ignored."""
        watcher, _ = _make_watcher()
        old_activity = watcher.last_activity
        time.sleep(0.05)
        watcher.on_modified(_make_mock_event("/tmp/input/not_in_pending.exe"))
        assert watcher.last_activity == old_activity

    def test_on_created_directory_ignored(self):
        """Directory creation events should be ignored."""
        watcher, _ = _make_watcher()
        event = _make_mock_event("/tmp/input/newdir", is_directory=True)
        watcher.on_created(event)
        assert watcher.get_pending_count() == 0


class TestBatchDispatch:
    def test_batch_not_dispatched_before_delay(self):
        """Batch should not dispatch before batch_delay seconds have passed."""
        watcher, callback = _make_watcher(delay=10)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=100):
                watcher.on_created(_make_mock_event("/tmp/input/test.exe"))
        # Immediately check batch - should not dispatch
        watcher._check_batch_ready()
        callback.assert_not_called()

    def test_batch_dispatches_after_delay(self):
        """Batch should dispatch after batch_delay seconds of inactivity."""
        watcher, callback = _make_watcher(delay=0.1)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=100):
                watcher.on_created(_make_mock_event("/tmp/input/test.exe"))
        # Wait for batch_delay
        time.sleep(0.2)
        watcher._check_batch_ready()
        callback.assert_called_once()

    def test_batch_not_dispatched_with_pending_empty(self):
        """_check_batch_ready with empty pending should return immediately."""
        watcher, callback = _make_watcher()
        # pending_files is empty
        watcher._check_batch_ready()
        callback.assert_not_called()

    def test_max_batch_limits_dispatched_files(self):
        """max_batch should limit the number of files dispatched per batch."""
        watcher, callback = _make_watcher(delay=0.1, max_batch=2)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=100):
                for i in range(5):
                    watcher.on_created(_make_mock_event(f"/tmp/input/file{i}.exe"))
        time.sleep(0.2)
        watcher._check_batch_ready()
        # Should dispatch only 2 files
        call_args = callback.call_args
        assert len(call_args[0][0]) == 2

    def test_max_batch_zero_is_unlimited(self):
        """max_batch=0 (unlimited) should dispatch all pending files."""
        watcher, callback = _make_watcher(delay=0.1, max_batch=0)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=100):
                for i in range(3):
                    watcher.on_created(_make_mock_event(f"/tmp/input/file{i}.exe"))
        time.sleep(0.2)
        watcher._check_batch_ready()
        call_args = callback.call_args
        assert len(call_args[0][0]) == 3

    def test_get_pending_count_after_dispatch(self):
        """Pending count should decrease after batch dispatch."""
        watcher, callback = _make_watcher(delay=0.1)
        with mock.patch("os.path.exists", return_value=True):
            with mock.patch("os.path.getsize", return_value=100):
                for i in range(3):
                    watcher.on_created(_make_mock_event(f"/tmp/input/file{i}.exe"))
        assert watcher.get_pending_count() == 3
        time.sleep(0.2)
        watcher._check_batch_ready()
        assert watcher.get_pending_count() == 0

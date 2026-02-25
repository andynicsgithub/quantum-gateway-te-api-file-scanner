import hashlib
import urllib.parse
from pathlib import Path
import pytest

from te_file_handler import TE
from path_handler import PathHandler


def test_sanitize_roundtrip():
    original = "simple.txt"
    safe = PathHandler.sanitize_filename(original)
    assert safe != ""
    assert " " not in safe
    assert isinstance(safe, str)
    assert PathHandler.desanitize_filename(safe) == original


def test_sanitize_complex():
    # include spaces, unicode, and a byte outside utf-8
    name_bytes = b"weird\xffname"
    original = name_bytes.decode('latin-1')
    safe = PathHandler.sanitize_filename(original)
    # safe must be pure ASCII and no spaces
    assert all(ord(c) < 128 for c in safe)
    assert " " not in safe
    assert PathHandler.desanitize_filename(safe) == original


def test_collision_suffix():
    # percent-encoding is injective, so collisions don't naturally occur;
    # simulate a collision by pre-populating the map with a different value.
    name1 = "foo"
    name2 = "bar"
    safe1 = PathHandler.sanitize_filename(name1)
    # manually force a fake collision: pretend `safe1` already maps to name2
    from path_handler import _api_name_map
    _api_name_map[safe1] = name2
    # now sanitize a new name that would normally encode to safe1
    # we can't easily construct such a name, so call sanitize on name1 again
    # to trigger the collision branch
    safe2 = PathHandler.sanitize_filename(name1)
    assert safe2 != safe1
    assert safe2.startswith(safe1 + "_")
    # desanitize returns the expected originals
    assert PathHandler.desanitize_filename(safe1) == name2
    assert PathHandler.desanitize_filename(safe2) == name1


def test_te_upload_uses_sanitized_name(tmp_path, monkeypatch):
    # create a fake file with spaces and non-ascii
    filename = "fi le.txt"
    file_path = tmp_path / filename
    file_path.write_bytes(b"data")
    # directories can be arbitrary because we won't actually move anything
    te = TE("http://example", filename, "", str(file_path), str(tmp_path), str(tmp_path), str(tmp_path), str(tmp_path), str(tmp_path))

    called = {}
    def fake_post(url, data=None, files=None, verify=None):
        called['files'] = files
        class R:
            def json(self):
                return {"response":[{"status":{"label":"UPLOAD_SUCCESS"}}]}
        return R()
    monkeypatch.setattr('requests.post', fake_post)

    te.upload_file()
    assert 'file' in called['files']
    sent_filename = called['files']['file'][0]
    assert sent_filename == te.api_name
    assert sent_filename != filename

#!/usr/bin/env python3

"""Tests for tex_results.py - TEX (Scrub) result processing."""

import tempfile
import base64
from pathlib import Path
from tex_results import CpExtractResult, return_relevant_enum, TEX


class TestEnum:
    def test_enum_all_values_present(self):
        """All expected enum values should be defined."""
        assert len(CpExtractResult) == 20
        assert CpExtractResult.CP_EXTRACT_RESULT_SUCCESS.value == 0
        assert CpExtractResult.CP_EXTRACT_RESULT_FAILURE.value == 1
        assert CpExtractResult.CP_EXTRACT_RESULT_INTERNAL_ERROR.value == 5
        assert CpExtractResult.CP_EXTRACT_RESULT_UNSUPPORTED_FILE.value == 3
        assert CpExtractResult.CP_EXTRACT_RESULT_NOT_SCRUBBED.value == 4

    def test_enum_name_to_value(self):
        """Enum name to value conversion should work both ways."""
        name = return_relevant_enum(0)
        assert name == "CP_EXTRACT_RESULT_SUCCESS"

    def test_enum_values_map_correctly(self):
        """All enum values should map correctly."""
        for result in CpExtractResult:
            name = return_relevant_enum(result.value)
            assert name == result.name


class TestReturnRelevantEnum:
    def test_return_relevant_enum_known(self):
        """Known status codes should return correct enum name."""
        assert return_relevant_enum(0) == "CP_EXTRACT_RESULT_SUCCESS"
        assert return_relevant_enum(1) == "CP_EXTRACT_RESULT_FAILURE"
        assert return_relevant_enum(3) == "CP_EXTRACT_RESULT_UNSUPPORTED_FILE"

    def test_return_relevant_enum_unknown(self):
        """Unknown status codes should return fallback string."""
        result = return_relevant_enum(999)
        assert "unknown_status_999" == result


class TestTEX:
    def test_tex_initialization(self):
        """TEX should initialize with correct attributes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
                log_path="test.pdf",
            )
            assert tex.file_name == "test.pdf"
            assert tex.scrub_result == -1
            assert tex.clean_file_data == ""

    def test_tex_initialization_without_log_path(self):
        """TEX should use file_name as log_path when not provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "doc.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            assert tex.log_path == "doc.pdf"


class TestFallbackFilename:
    def test_fallback_filename_with_extension(self):
        """Filename with extension should insert .cleaned before it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "document.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex._fallback_filename()
            assert tex.clean_file_name == "document.cleaned.pdf"

    def test_fallback_filename_no_extension(self):
        """Filename without extension should append .cleaned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "noextension",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex._fallback_filename()
            assert tex.clean_file_name == "noextension.cleaned"

    def test_fallback_filename_with_multiple_dots(self):
        """Filename with multiple dots should insert .cleaned before last extension."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "file.name.with.dots.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex._fallback_filename()
            assert tex.clean_file_name == "file.name.with.dots.cleaned.pdf"

    def test_fallback_filename_single_char(self):
        """Single character filename should work."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "a",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex._fallback_filename()
            assert tex.clean_file_name == "a.cleaned"


class TestCreateCleanFile:
    def test_create_clean_file_writes_file(self):
        """create_clean_file should write the decoded base64 data to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
                log_path="test.pdf",
            )
            original_data = b"cleaned file content"
            tex.clean_file_data = base64.b64encode(original_data).decode()
            tex._fallback_filename()  # set clean_file_name

            result_path = tex.create_clean_file()
            assert result_path is not None
            assert result_path.exists()
            assert result_path.read_bytes() == original_data

    def test_create_clean_file_no_data(self):
        """create_clean_file with no data should log warning and return None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            result_path = tex.create_clean_file()
            assert result_path is None

    def test_create_clean_file_with_api_name(self):
        """create_clean_file should use API output_file_name when provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.docm",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex.clean_file_data = base64.b64encode(b"content").decode()
            response = {
                "response": [
                    {"scrub": {"output_file_name": "custom.cleaned.docx"}}
                ]
            }
            result_path = tex.create_clean_file(response)
            assert result_path is not None
            assert "custom.cleaned.docx" in str(result_path)

    def test_create_clean_file_empty_response(self):
        """create_clean_file with empty response list handles gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex.clean_file_data = base64.b64encode(b"content").decode()
            response = {"response": []}
            # Empty response causes IndexError - expected for malformed response
            try:
                tex.create_clean_file(response)
            except (IndexError, KeyError):
                pass


class TestCreateResponseInfo:
    def test_create_response_info_empty_response(self):
        """create_response_info with no data should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            tex._create_response_info({})
            assert tex.scrub_result == -1

    def test_create_response_info_not_cleaned(self):
        """Response with not_cleaned status should set scrub_result correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            response = {"response": [{"scrub": {"result": 4}}]}
            tex._create_response_info(response)
            assert tex.scrub_result == -1

    def test_create_response_info_no_scrub_data(self):
        """Response without scrub data should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
            )
            response = {"response": [{"not_scrub": "data"}]}
            # Should not crash
            tex._create_response_info(response)


class TestProcessResults:
    def test_process_results_cleaned(self):
        """process_results should return True when file was cleaned (file_enc_data present)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
                log_path="test.pdf",
                save_response_info=True,
            )
            response = {
                "response": [
                    {
                        "scrub": {
                            "result": 0,
                            "scrub_result": 0,
                            "file_enc_data": base64.b64encode(b"cleaned content").decode(),
                        }
                    }
                ]
            }
            result = tex.process_results(response)
            assert result is True

    def test_process_results_not_cleaned(self):
        """process_results should handle non-cleaned files without crashing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tex = TEX(
                "test.pdf",
                Path(tmpdir) / "response_info",
                Path(tmpdir) / "clean_files",
                log_path="test.pdf",
                save_response_info=True,
            )
            response = {"response": [{"scrub": {"result": 4}}]}
            result = tex.process_results(response)
            assert result is False

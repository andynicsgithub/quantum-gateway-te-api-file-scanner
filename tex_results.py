#!/usr/bin/env python3

"""
tex_results.py
Handles TEX (Threat Extraction / Scrub) results from file upload responses.
Extracts scrub results, writes response info, and creates cleaned files when TEX
manages to scrub the file.
"""

import copy
import json
import base64
import logging
from pathlib import Path
from enum import Enum


# ~~~~~~~~~ TEX statuses ~~~~~~~~~ #

class CpExtractResult(Enum):
    CP_EXTRACT_RESULT_CANCEL_SCRUBBING = -1
    CP_EXTRACT_RESULT_SUCCESS = 0
    CP_EXTRACT_RESULT_FAILURE = 1
    CP_EXTRACT_RESULT_TIMEOUT = 2
    CP_EXTRACT_RESULT_UNSUPPORTED_FILE = 3
    CP_EXTRACT_RESULT_NOT_SCRUBBED = 4
    CP_EXTRACT_RESULT_INTERNAL_ERROR = 5
    CP_EXTRACT_RESULT_DISK_LIMIT_REACHED = 6
    CP_EXTRACT_RESULT_ENCRYPTED_FILE = 7
    CP_EXTRACT_RESULT_DOCSEC_FILE = 8
    CP_EXTRACT_RESULT_OUT_OF_MEMORY = 9
    CP_EXTRACT_RESULT_SKIPPED_BY_SCRIPT = 10
    CP_EXTRACT_RESULT_SKIPPED_BY_TE_CONFIDENCE = 11
    CP_EXTRACT_RESULT_NO_VALID_CONTRACT = 12
    CP_EXTRACT_RESULT_BYPASS_SCRUB = 13
    CP_EXTRACT_RESULT_BYPASS_FILE_SCRUB = 14
    CP_EXTRACT_RESULT_ENCRYPTED_FILE_OR_SIGNED = 15
    CP_EXTRACT_RESULT_WATERMARK_FAILED = 16
    CP_EXTRACT_RESULT_FILE_LARGER_THAN_LIMIT = 17
    CP_EXTRACT_NUM_RESULTS = 18


def return_relevant_enum(status):
    """
    Convert a TEX status code to its named enum value.
    """
    return CpExtractResult(status).name


class TEX(object):
    """
    Parses and processes TEX (Scrub) results from a file upload response.
    
    After a file is uploaded with TEX enabled, the upload response contains
    scrub results. This class:
    1. Extracts the scrub response and writes it to tex_response_info/
    2. If TEX successfully cleaned the file, creates the cleaned file in
       tex_clean_files/ with a .cleaned filename pattern
    
    Usage:
        tex = TEX(file_name, tex_response_info_dir, tex_clean_files_dir)
        tex.process_results(upload_response)
    """
    
    def __init__(self, file_name, output_folder_tex_response_info, output_folder_tex_clean_files):
        self.file_name = file_name
        self.output_folder_tex_response_info = Path(output_folder_tex_response_info)
        self.output_folder_tex_clean_files = Path(output_folder_tex_clean_files)
        self.clean_file_data = ""
        self.clean_file_name = ""
        self.scrub_result = -1
        self.logger = logging.getLogger('te_scanner.tex')
    
    def create_clean_file(self):
        """
        Decode the cleaned file content received as base64 in the response and
        write it to a new file with .cleaned filename pattern in tex_clean_files/.
        
        Example: "document.pdf" -> "document.cleaned.pdf"
        
        Returns:
            Path to the created cleaned file
        """
        text = base64.b64decode(self.clean_file_data)
        
        # Build cleaned filename: name.ext -> name.cleaned.ext
        parts = self.file_name.rsplit('.', 1)
        if len(parts) == 2:
            self.clean_file_name = f"{parts[0]}.cleaned.{parts[1]}"
        else:
            self.clean_file_name = f"{self.file_name}.cleaned"
        
        output_path = self.output_folder_tex_clean_files / self.clean_file_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'wb') as file:
            file.write(text)
        
        return output_path
    
    def process_results(self, response):
        """
        Process TEX results from an upload response.
        
        1. Creates TEX response info file in tex_response_info/
        2. If TEX cleaned the file, creates the cleaned file in tex_clean_files/
        
        Args:
            response: The full upload response dict containing scrub results
            
        Returns:
            bool: True if TEX cleaned the file, False otherwise
        """
        try:
            is_cleaned = self._create_response_info(response)
            if is_cleaned:
                cleaned_file_path = self.create_clean_file()
                self.logger.info(f"TEX cleaned file: {cleaned_file_path}")
                self.logger.info(f"TEX extract result: {return_relevant_enum(self.scrub_result)}")
            else:
                self.logger.info(f"TEX extract result: {return_relevant_enum(self.scrub_result)}")
            return is_cleaned
        except Exception as E:
            self.logger.error(f"Processing TEX results failed for {self.file_name}: {E}", exc_info=True)
            raise
    
    def _create_response_info(self, response):
        """
        Extract scrub response from the upload response and write it to a file.
        
        Args:
            response: Full upload response dict
            
        Returns:
            bool: True if the file was cleaned, False otherwise
        """
        try:
            scrub_response = response["response"][0]["scrub"]
        except (KeyError, IndexError) as E:
            self.logger.error(f"No scrub data in response for {self.file_name}: {E}")
            return False
        
        # Check if file was cleaned (empty file_enc_data means not cleaned)
        is_cleaned = scrub_response.get("file_enc_data", "") != ""
        
        # Save scrub result code for logging
        self.scrub_result = scrub_response.get("scrub_result", -1)
        
        # Store clean file data before potentially removing it from the response
        self.clean_file_data = copy.deepcopy(scrub_response.get("file_enc_data", ""))
        
        # Build response filename
        response_filename = f"{self.file_name}.response.txt"
        output_path = self.output_folder_tex_response_info / response_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove clean file data from response to save space in response file
        if is_cleaned:
            scrub_response_copy = copy.deepcopy(scrub_response)
            scrub_response_copy["file_enc_data"] = "[removed - already used for cleaned file]"
        else:
            scrub_response_copy = scrub_response
        
        self.logger.info(f"TEX Upload response: {json.dumps(scrub_response_copy, indent=2)}")
        
        with open(output_path, 'w') as file:
            file.write(json.dumps(scrub_response_copy, indent=2))
        
        return is_cleaned

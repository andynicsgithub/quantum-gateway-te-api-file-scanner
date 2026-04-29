#!/usr/bin/env python3

"""
te_file_handler v10.0 (alpha)
A Python module for handling individual file processing via the Threat Emulation API.
Features:
  - Checks TE cache before upload
  - Uploads files to the TE appliance
  - Queries TE, TE_EB and TEX results until final verdict
  - Downloads TE reports for malicious files
  - Moves files to benign_directory, quarantine_directory, or error_directory based on verdict
  - Pretty-prints JSON response output
  - Processes TEX (Scrub) results from upload response

Changes in v10.0 over v9.2:
  1. Added TEX (Threat Extraction/Scrub) result processing after upload
  2. TE class accepts url_tex and tex_api_key parameters
  3. TEX results written to tex_response_info/ and cleaned files to tex_clean_files/
  4. TEX errors are non-blocking — TE processing continues on TEX failure

Changes in v9.0 over v8.00:
  1. Added SMTP email notification integration support

Changes in v7.01 over v6.3:
  1. No changes in this file. Changes were made in other files that are part of the application.


Changes in v6.3 over v6.2:
Comments / Notes:
-----------------
  1. TE class handles a single file at a time:
     - Queries TE cache by SHA1 before uploading
     - Uploads file if not found
     - Polls TE and TE_EB results until final verdict
  2. Moves files based on verdict into benign_directory, quarantine_directory, or error_directory.
  3. Downloads TE reports for malicious files and saves them under reports_directory,
     preserving subdirectory structure from input_directory.
  4. SHA1 is calculated in 1KB blocks for memory efficiency.
  5. Uses deep copy of request template to safely modify per file.
  6. Implements retries for query with MAX_RETRIES and SECONDS_TO_WAIT interval.
  7. Exception handling:
     - Upload errors → move to error_directory
     - Other errors logged but do not stop processing of other files
  8. Supports nested subdirectories via sub_dir argument to preserve folder structure.
  9. All printed messages include file path for easier debugging.
"""

import json
import requests
import base64
import os
import hashlib
import time
import tarfile
import copy
import urllib3
import shutil
import logging
from pathlib import Path
from path_handler import PathHandler
from zip_archive import ZipArchiveManager
from tex_results import TEX
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


SECONDS_TO_WAIT = 15
MAX_RETRIES = 120


class TE(object):
    """
    This class gets a file as input and handles it as follows (function handle_file) :
     1. Query TE cache by the file sha1 for already existing TE results.
     2. If not found in TE cache then :
       2.1 Upload the file to the appliance for handling by te and te_eb features.
       2.2 If upload result is upload_success (meaning no TE results yet) then :
             Query te and te_eb features until receiving TE results.
               If in between receiving te_eb found results of the early malicious verdict, then display the verdict.
     3. Write the TE results (last query/upload response info) into the output folder.
          If resulted TE verdict is malicious then also download the TE report and write it into the output folder.
    """
    def __init__(self, url, url_tex, file_name, sub_dir, full_path, input_directory, reports_directory, benign_directory, quarantine_directory, error_directory, tex_api_key='', zip_config=None, config=None):
        self.url = url
        self.url_tex = url_tex
        self.file_name = file_name
        self.sub_dir = sub_dir
        # Convert to Path objects for cross-platform compatibility
        self.full_path = Path(full_path) if not isinstance(full_path, Path) else full_path
        self.input_directory = Path(input_directory) if not isinstance(input_directory, Path) else input_directory
        self.reports_directory = Path(reports_directory) if not isinstance(reports_directory, Path) else reports_directory
        self.benign_directory = Path(benign_directory) if not isinstance(benign_directory, Path) else benign_directory
        self.quarantine_directory = Path(quarantine_directory) if not isinstance(quarantine_directory, Path) else quarantine_directory
        self.error_directory = Path(error_directory) if not isinstance(error_directory, Path) else error_directory
        self.tex_api_key = tex_api_key
        self.config = config
        # zip_config: (zip_path, zip_password, benign_basename, quarantine_basename, error_basename)
        # For multiprocessing: passed as tuple since ZipArchiveManager can't be shared across processes
        # For watch mode (single process): can be a ZipArchiveManager instance
        self.zip_config = zip_config
        self.sha1 = ""
        self.final_response = ""
        self.final_status_label = ""
        self.report_id = ""
        self._tex_status = None
        self.logger = logging.getLogger('te_scanner.file_handler')
        self.request_template = {
            "request": [{
                "features": ["te", "te_eb"],
                "te": {
                    "reports": ["summary"],
                    "version_info": True,
                    "return_errors": True
                }
            }]
        }




    def set_file_sha1(self):
        """
        Calculates the file's sha1
        """
        sha1 = hashlib.sha1()
        with open(str(self.full_path), 'rb') as f:
            while True:
                block = f.read(2 ** 10)  # One-kilobyte blocks
                if not block:
                    break
                sha1.update(block)
            self.sha1 = sha1.hexdigest()

    def parse_verdict(self, response, feature):
        """
        Parsing the verdict of handled feature results response, in case the that feature response status is FOUND.
        :param response: the handled response
        :param feature: either "te" or "te_eb"
        :return the verdict
        """
        verdict = response["response"][0][feature]["combined_verdict"]
        self.logger.info("{} - {} verdict is: {}".format(self.file_name, feature, verdict))
        return verdict

    def parse_report_id(self, response):
        """
        parse and return the summary report id
        :param response: the (last) response with the handled file TE results
        """
        try:
            self.report_id = response["response"][0]["te"]["summary_report"]
        except Exception as E:
            self.logger.error("Could not get TE report id, failure: {}. ".format(E))

    def create_response_info(self, response):
        """
        Create the TE response info of handled file and write it into the output folder.
        :param response: last response
        """
        output_path = self.reports_directory / self.sub_dir
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / (self.file_name + ".response.txt")
        self.logger.debug(f"self.reports_directory: {self.reports_directory}")
        self.logger.debug(f"self.sub_dir: {self.sub_dir}")
        self.logger.debug(f"self.file_name: {self.file_name}")
        self.logger.debug(f"{output_file}")
        with open(str(output_file), 'w') as file:
            file.write(json.dumps(response, indent=4))
            
    def check_te_cache(self):
        """
        Query (for te) the file (before upload) in order to find whether file results already exist in TE cache.
        :return the query response
        """
        self.set_file_sha1()
        request = copy.deepcopy(self.request_template)
        request['request'][0]['features'].remove('te_eb')
        request['request'][0]['sha1'] = self.sha1
        self.logger.info(f"{self.file_name} - sha1: {self.sha1}")
        data = json.dumps(request)
        self.logger.debug("Sending TE Query request before upload in order to check TE cache")
        response = requests.post(url=self.url + "query", data=data, verify=False)
        response_j = response.json()
        return response_j

    def upload_file(self):
        """
        Upload the file to the appliance for te and te_eb and get the upload response.
        :return the upload response
        """
        request = copy.deepcopy(self.request_template)
        data = json.dumps(request)
        self.logger.debug("Sending Upload request of te and te_eb")
        try:
            with open(str(self.full_path), 'rb') as f:
                curr_file = {
                    'request': data,
                    'file': f
                }
                response = requests.post(url=self.url + "upload", files=curr_file, verify=False)
        except Exception as E:
            self.logger.error("Upload file failed: {}".format(E))
            self.move_file(self.error_directory)            
            raise
        response_j = response.json()
        self.logger.info("te and te_eb Upload response status : {}".format(response_j["response"][0]["status"]["label"]))
        return response_j

    def query_file(self):
        """
        Query the appliance for te and te_eb of the file every SECONDS_TO_WAIT seconds.
        Repeat query until receiving te results.  te_eb results of early malicious verdict might be received earlier.
        :return the (last) query response with the handled file TE results
        """
        self.logger.debug("Start sending Query requests of te and te_eb after TE upload")
        time.sleep(SECONDS_TO_WAIT)
        request = copy.deepcopy(self.request_template)
        request['request'][0]['sha1'] = self.sha1
        data = json.dumps(request)
        response_j = json.loads('{}')
        status_label = False
        te_eb_found = False
        retry_no = 0
        while (not status_label) or (status_label == "PENDING") or (status_label == "PARTIALLY_FOUND"):
            self.logger.debug("Sending Query request of te and te_eb")
            response = requests.post(url=self.url + "query", data=data, verify=False)
            response_j = response.json()
            status_label = response_j['response'][0]['status']['label']
            if (status_label != "PENDING") and (status_label != "PARTIALLY_FOUND"):
                break
            if status_label == "PARTIALLY_FOUND":
                if not te_eb_found:
                    te_eb_status_label = response_j["response"][0]["te_eb"]['status']['label']
                    if te_eb_status_label == "FOUND":
                        te_eb_found = True
                        te_eb_verdict = self.parse_verdict(response_j, "te_eb")
                        if te_eb_verdict == "Malicious":
                            self.logger.debug("Early verdict is malicious")
                            self.logger.debug("Continue Query until receiving te results")
                te_status_label = response_j["response"][0]["te"]['status']['label']
                if (te_status_label == "FOUND") or (te_status_label == "NOT_FOUND"):
                    break
                elif te_status_label == "PARTIALLY_FOUND":
                    te_images_j_arr = response_j["response"][0]["te"]["images"]
                    no_pending_image = True
                    for image_j in te_images_j_arr:
                        if image_j["status"] == "pending":
                            no_pending_image = False
                            break
                    if no_pending_image:
                        break
            self.logger.debug("te and te_eb Query response status : {}".format(status_label))
            time.sleep(SECONDS_TO_WAIT)
            retry_no += 1
            if retry_no == MAX_RETRIES:
                self.logger.debug("Reached query max retries.  Stop waiting for te results for")
                break
        return response_j

    def download_report(self):
        """
        Download the TE report to the appliance and save it as a .tgz file
        """
        try:
            self.logger.debug("Sending Download request for TE report")
            response = requests.get(url=self.url + "download?id=" + self.report_id, verify=False)
            encoded_content_string = response.text
            decoded_content = base64.b64decode(encoded_content_string)
            decoded_report_archive_path = self.reports_directory / self.sub_dir / (self.file_name + ".report.tar.gz")
            
            # Ensure the directory for the report exists
            decoded_report_archive_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the content to the file
            with open(decoded_report_archive_path, "wb") as decoded_report_archive_file:
                decoded_report_archive_file.write(decoded_content)
            
            self.logger.debug("TE report downloaded to: {}".format(decoded_report_archive_path))
        except Exception as E:
            self.logger.error("Downloading TE report failed:  {} ".format(E))


    def _setup_tex_directories(self, config):
        """
        Create TEX output directories under reports_directory.
        """
        self.tex_response_info_dir = self.reports_directory / config.tex_response_info_directory
        self.tex_clean_files_dir = self.reports_directory / config.tex_clean_files_directory
        self.tex_response_info_dir.mkdir(parents=True, exist_ok=True)
        self.tex_clean_files_dir.mkdir(parents=True, exist_ok=True)
    
    def _set_file_md5(self):
        """
        Calculates the file's md5 hash.
        """
        md5 = hashlib.md5()
        with open(str(self.full_path), 'rb') as f:
            while True:
                block = f.read(2 ** 10)
                if not block:
                    break
                md5.update(block)
        return md5.hexdigest()
    
    def _upload_for_tex(self, config):
        """
        Upload file to the TPAPI endpoint for TEX (Scrub) processing.
        This is a separate upload from the TE Cloud API upload.
        TPAPI uses a different request format with scrub_options.
        
        Args:
            config: ScannerConfig object
            
        Returns:
            The upload response dict from TPAPI, or None on failure
        """
        if not self.url_tex or not self.tex_api_key:
            return None
        
        # Check if file type is enabled for TEX processing
        file_ext = self.file_name.rsplit('.', 1)[-1].lower() if '.' in self.file_name else ''
        if config.tex_supported_file_types and file_ext not in config.tex_supported_file_types:
            self.logger.info(f"Skipping TEX — file type not enabled: {self.file_name} ({file_ext})")
            return None
        
        try:
            self._setup_tex_directories(config)
            self.logger.info(f"Uploading to TPAPI for TEX processing: {self.url_tex}")
            
            md5 = self._set_file_md5()
            self.logger.debug(f"File MD5: {md5}")
            
            # Use configured scrubbed parts codes
            scrubbed_parts = sorted(config.tex_scrubbed_parts_codes) if config.tex_scrubbed_parts_codes else [1018, 1019, 1021, 1025, 1026, 1034, 1137, 1139, 1141, 1142, 1143, 1150, 1151]
            
            # Build TPAPI upload request
            request = {
                "request": [{
                    "protocol_version": "1.1",
                    "api_key": self.tex_api_key,
                    "request_name": "UploadFile",
                    "file_orig_name": self.file_name,
                    "te_options": {
                        "file_name": self.file_name,
                        "file_type": file_ext,
                        "is_base64": True,
                        "features": ["te", "te_eb", "av"],
                        "te": {
                            "reports": ["summary"]
                        }
                    },
                    "scrub_options": {
                        "scrub_method": 1,
                        "scrubbed_parts_codes": scrubbed_parts,
                        "save_original_file_on_server": False
                    }
                }]
            }
            
            # Encode file as base64
            with open(str(self.full_path), 'rb') as f:
                file_b64 = base64.b64encode(f.read()).decode("utf-8")
            request['request'][0]['file_enc_data'] = str(file_b64)
            
            data = json.dumps(request)
            
            try:
                response = requests.post(
                    url=self.url_tex,
                    data=data,
                    headers={'Content-Type': 'application/json'},
                    verify=False,
                    timeout=300
                )
            except Exception as E:
                self.logger.error(f"TPAPI upload request failed: {E}")
                return None
            
            response_j = response.json()
            return response_j
            
        except Exception as E:
            self.logger.error(f"TEX upload preparation failed for {self.file_name}: {E}", exc_info=True)
            return None
    
    def _process_tex_results(self, config):
        """
        Upload file to TPAPI and process TEX (Scrub) results.
        This is a separate flow from TE Cloud API processing.
        
        Sets self._tex_status to:
            'cleaned'     - TEX successfully removed malicious parts
            'not_cleaned' - TEX processed but found nothing to remove
            'unsupported' - File type not supported by TEX
        None = TEX was not processed
        
        Args:
            config: ScannerConfig object with tex_* fields
        """
        if not self.url_tex or not self.tex_api_key:
            self._tex_status = None
            return
        
        file_ext = self.file_name.rsplit('.', 1)[-1].lower() if '.' in self.file_name else ''
        if config.tex_supported_file_types and file_ext not in config.tex_supported_file_types:
            self._tex_status = 'unsupported'
            self.logger.info(f"Skipping TEX — file type not enabled: {self.file_name} ({file_ext})")
            return
        
        try:
            upload_response = self._upload_for_tex(config)
            if upload_response is None:
                self.logger.warning(f"TEX upload returned no response for {self.file_name}")
                return
            
            scrub_info = upload_response.get('response', [{}])[0].get('scrub', {})
            self.logger.debug(f"TEX upload response status: {scrub_info.get('scrub_result', 'unknown')}")
            
            tex = TEX(
                self.file_name,
                self.tex_response_info_dir,
                self.tex_clean_files_dir
            )
            is_cleaned = tex.process_results(upload_response)
            if is_cleaned:
                self._tex_status = 'cleaned'
                self.logger.info(f"TEX cleaned file: {tex.clean_file_name}")
            else:
                self._tex_status = 'not_cleaned'
                self.logger.info(f"TEX processed but found nothing to remove: {self.file_name}")
            
        except Exception as E:
            self.logger.warning(f"TEX processing failed for {self.file_name}: {E}")
            # TEX errors are non-blocking - continue with TE processing


    def handle_file(self):
        """
        (Function description is within above class description)
        """
        query_cache_response = self.check_te_cache()
        cache_status_label = query_cache_response['response'][0]['status']['label']
        if cache_status_label == "FOUND":
            self.logger.debug("Results already exist in TE cache")
            self.final_response = query_cache_response
            self.final_status_label = cache_status_label
        else:
            self.logger.debug("No results in TE cache before upload")
            upload_response = self.upload_file()
            upload_status_label = upload_response["response"][0]["status"]["label"]
            if upload_status_label == "UPLOAD_SUCCESS":
                query_response = self.query_file()
                query_status_label = query_response["response"][0]["status"]["label"]
                self.logger.debug("Receiving Query response with te results. status: {}".format(query_status_label))
                self.final_response = query_response
                self.final_status_label = query_status_label
            else:
                self.final_response = upload_response
                self.final_status_label = upload_status_label
        self.create_response_info(self.final_response)
        
        # Process TEX via separate TPAPI upload (independent of TE Cloud flow)
        if self.url_tex and self.tex_api_key:
            self._process_tex_results(self.config)

        if self.final_status_label == "FOUND":
            self.logger.debug("move_file called")
            verdict = self.parse_verdict(self.final_response, "te")
            # Get last path component robustly - works for UNC, local, trailing slashes
            def get_dir_basename(path_obj):
                p = str(path_obj).rstrip('/\\')
                idx = max(p.rfind('/'), p.rfind('\\'))
                return p[idx+1:] if idx >= 0 else p
            self.logger.info(f"[ZIP] verdict={verdict}, dirs: benign={self.benign_directory!r} quarantine={self.quarantine_directory!r} error={self.error_directory!r}")
            if verdict == "Malicious":
                basename = get_dir_basename(self.quarantine_directory)
                self.logger.info(f"[ZIP] Malicious: basename={basename!r}")
                self._add_to_zip(basename)
                self.move_file(self.quarantine_directory)
                self.parse_report_id(self.final_response)
                if self.report_id != "":
                    self.download_report()
            elif verdict == "Benign":
                basename = get_dir_basename(self.benign_directory)
                self.logger.info(f"[ZIP] Benign: basename={basename!r}")
                self._add_to_zip(basename)
                self.move_file(self.benign_directory)
            elif verdict == "Error":
                basename = get_dir_basename(self.error_directory)
                self.logger.info(f"[ZIP] Error: basename={basename!r}")
                self._add_to_zip(basename)
                self.move_file(self.error_directory)
                

    def _add_to_zip(self, verdict_basename=None):
        """
        Copy the file into the zip archive (or temp dir for multiprocessing)
        before moving it to the verdict directory.
        The file must still be at self.full_path when this is called.
        
        In single-process mode (watch mode): adds directly to ZipArchiveManager.
        In multiprocessing mode: copies file to temp directory for later consolidation.
        
        Args:
            verdict_basename: Directory name inside zip (e.g. 'benign', 'quarantine', 'error').
        """
        self.logger.info(f"[ZIP] _add_to_zip called for {self.file_name}, zip_config type={type(self.zip_config).__name__}, basename={verdict_basename}")
        
        if self.zip_config is None:
            self.logger.warning(f"[ZIP] zip_config is None, skipping {self.file_name}")
            return
        
        if not verdict_basename:
            self.logger.warning(f"[ZIP] verdict_basename is empty, skipping {self.file_name}")
            return
        
        # Single-process mode (watch mode): ZipArchiveManager instance
        if isinstance(self.zip_config, ZipArchiveManager):
            self.logger.info(f"[ZIP] Single-process mode: adding {self.file_name} directly to zip")
            self.zip_config.add_file(self.full_path, verdict_basename, self.sub_dir, self.file_name)
            return
        
        # Multiprocessing mode: copy to temp directory for consolidation
        if not isinstance(self.zip_config, (list, tuple)):
            self.logger.warning(f"[ZIP] zip_config is not a ZipArchiveManager or tuple: {type(self.zip_config)}, skipping {self.file_name}")
            return
        
        # zip_config: (zip_path, zip_password, benign_basename, quarantine_basename, 
        #              error_basename, temp_dir)
        if len(self.zip_config) < 6:
            self.logger.warning(f"[ZIP] zip_config has only {len(self.zip_config)} elements, expected 6, skipping {self.file_name}")
            return
        
        temp_dir = self.zip_config[5]
        if not temp_dir:
            self.logger.warning(f"[ZIP] temp_dir is empty, skipping {self.file_name}")
            return
        
        self.logger.info(f"[ZIP] Multiprocessing mode: copying {self.file_name} to temp dir: {temp_dir}")
        
        try:
            dest_path = Path(temp_dir) / verdict_basename / self.sub_dir
            dest_path.mkdir(parents=True, exist_ok=True)
            dest_file = dest_path / self.file_name
            with open(str(self.full_path), 'rb') as src_f, open(str(dest_file), 'wb') as dst_f:
                while True:
                    chunk = src_f.read(65536)
                    if not chunk:
                        break
                    dst_f.write(chunk)
            self.logger.info(f"Copied {self.file_name} to temp for zip: {verdict_basename}/{self.sub_dir}/{self.file_name}")
        except Exception as e:
            self.logger.error(f"Failed to copy {self.file_name} to temp for zip: {e}", exc_info=True)
    
    def move_file(self, destination_directory):
        """
        Move the file from its current location to the specified destination directory.
        Uses PathHandler for cross-platform and network path support.
        :param destination_directory: The directory to which the file should be moved.
        """
        current_location = self.full_path
        destination_location = destination_directory / self.sub_dir / self.file_name
        
        # Use PathHandler for safe, cross-platform move with retry logic
        success, message = PathHandler.safe_move(current_location, destination_location)
        
        if success:
            self.logger.debug(message)
        else:
            self.logger.error(f"Failed to move file {self.file_name}. {message}")


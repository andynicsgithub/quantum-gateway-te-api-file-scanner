#!/usr/bin/env python3

"""
te_file_handler v6.3
A Python module for handling individual file processing via the Threat Emulation API.
Features:
  - Checks TE cache before upload
  - Uploads files to the TE appliance
  - Queries TE and TE_EB results until final verdict
  - Downloads TE reports for malicious files
  - Moves files to benign_directory, quarantine_directory, or error_directory based on verdict
  - Pretty-prints JSON response output

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
from pathlib import Path
from path_handler import PathHandler
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
    def __init__(self, url, file_name, sub_dir, full_path, input_directory, reports_directory, benign_directory, quarantine_directory, error_directory):
        self.url = url
        self.file_name = file_name
        self.sub_dir = sub_dir
        # Convert to Path objects for cross-platform compatibility
        self.full_path = Path(full_path) if not isinstance(full_path, Path) else full_path
        self.input_directory = Path(input_directory) if not isinstance(input_directory, Path) else input_directory
        self.reports_directory = Path(reports_directory) if not isinstance(reports_directory, Path) else reports_directory
        self.benign_directory = Path(benign_directory) if not isinstance(benign_directory, Path) else benign_directory
        self.quarantine_directory = Path(quarantine_directory) if not isinstance(quarantine_directory, Path) else quarantine_directory
        self.error_directory = Path(error_directory) if not isinstance(error_directory, Path) else error_directory
        self.sha1 = ""
        self.final_response = ""
        self.final_status_label = ""
        self.report_id = ""
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




    def print(self, msg):
        """
        Logging purpose
        """
        print("file {} : {}".format(self.full_path, msg))

    def set_file_sha1(self):
        """
        Calculates the file's sha1
        """
        sha1 = hashlib.sha1()
        with open(str(self.full_path), 'rb') as f:
            while True:
                block = f.read(2 ** 10)  # One-megabyte blocks
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
        self.print("{} verdict is: {}".format(feature, verdict))
        return verdict

    def parse_report_id(self, response):
        """
        parse and return the summary report id
        :param response: the (last) response with the handled file TE results
        """
        try:
            self.report_id = response["response"][0]["te"]["summary_report"]
        except Exception as E:
            self.print("Could not get TE report id, failure: {}. ".format(E))

    def create_response_info(self, response):
        """
        Create the TE response info of handled file and write it into the output folder.
        :param response: last response
        """
        output_path = self.reports_directory / self.sub_dir
        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / (self.file_name + ".response.txt")
        print(f"self.reports_directory: {self.reports_directory}")
        print(f"self.sub_dir: {self.sub_dir}")
        print(f"self.file_name: {self.file_name}")
        print(f"{output_file}")
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
        self.print("sha1: {}".format(self.sha1))
        data = json.dumps(request)
        self.print("Sending TE Query request before upload in order to check TE cache")
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
        curr_file = {
            'request': data,
            'file': open(str(self.full_path), 'rb')
        }
        self.print("Sending Upload request of te and te_eb")
        try:
            response = requests.post(url=self.url + "upload", files=curr_file, verify=False)
        except Exception as E:
            self.print("Upload file failed: {}".format(E))
            self.move_file(self.error_directory)            
            raise
        response_j = response.json()
        self.print("te and te_eb Upload response status : {}".format(response_j["response"][0]["status"]["label"]))
        return response_j

    def query_file(self):
        """
        Query the appliance for te and te_eb of the file every SECONDS_TO_WAIT seconds.
        Repeat query until receiving te results.  te_eb results of early malicious verdict might be received earlier.
        :return the (last) query response with the handled file TE results
        """
        self.print("Start sending Query requests of te and te_eb after TE upload")
        time.sleep(SECONDS_TO_WAIT)
        request = copy.deepcopy(self.request_template)
        request['request'][0]['sha1'] = self.sha1
        data = json.dumps(request)
        response_j = json.loads('{}')
        status_label = False
        te_eb_found = False
        retry_no = 0
        while (not status_label) or (status_label == "PENDING") or (status_label == "PARTIALLY_FOUND"):
            print()
            self.print("Sending Query request of te and te_eb")
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
                            self.print("Early verdict is malicious")
                            self.print("Continue Query until receiving te results")
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
            self.print("te and te_eb Query response status : {}".format(status_label))
            time.sleep(SECONDS_TO_WAIT)
            retry_no += 1
            if retry_no == MAX_RETRIES:
                self.print("Reached query max retries.  Stop waiting for te results for")
                break
        return response_j

    def download_report(self):
        """
        Download the TE report to the appliance and save it as a .tgz file
        """
        try:
            self.print("Sending Download request for TE report")
            response = requests.get(url=self.url + "download?id=" + self.report_id, verify=False)
            encoded_content_string = response.text
            decoded_content = base64.b64decode(encoded_content_string)
            decoded_report_archive_path = self.reports_directory / self.sub_dir / (self.file_name + ".report.tar.gz")
            
            # Ensure the directory for the report exists
            decoded_report_archive_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write the content to the file
            with open(str(decoded_report_archive_path), "wb") as decoded_report_archive_file:
                decoded_report_archive_file.write(decoded_content)
            
            self.print("TE report downloaded to: {}".format(decoded_report_archive_path))
        except Exception as E:
            self.print("Downloading TE report failed:  {} ".format(E))


    def handle_file(self):
        """
        (Function description is within above class description)
        """
        query_cache_response = self.check_te_cache()
        cache_status_label = query_cache_response['response'][0]['status']['label']
        if cache_status_label == "FOUND":
            self.print("Results already exist in TE cache")
            self.final_response = query_cache_response
            self.final_status_label = cache_status_label
        else:
            self.print("No results in TE cache before upload")
            upload_response = self.upload_file()
            upload_status_label = upload_response["response"][0]["status"]["label"]
            if upload_status_label == "UPLOAD_SUCCESS":
                query_response = self.query_file()
                query_status_label = query_response["response"][0]["status"]["label"]
                self.print("Receiving Query response with te results. status: {}".format(query_status_label))
                self.final_response = query_response
                self.final_status_label = query_status_label
            else:
                self.final_response = upload_response
                self.final_status_label = upload_status_label
        self.create_response_info(self.final_response)

        if self.final_status_label == "FOUND":
            self.print("move_file called")
            verdict = self.parse_verdict(self.final_response, "te")
            if verdict == "Malicious":
                self.move_file(self.quarantine_directory)
                self.parse_report_id(self.final_response)
                if self.report_id != "":
                    self.download_report()
            elif verdict == "Benign":
                self.move_file(self.benign_directory)
            elif verdict == "Error":
                self.move_file(self.error_directory)
                

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
            self.print(message)
        else:
            self.print(f"Failed to move file {self.file_name}. {message}")


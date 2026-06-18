#!/usr/bin/env python3

"""
av_handler.py v12.0 (alpha)
Antivirus (AV) fallback handler for files too large for TE or unsupported by TE.

Uses SCP (via SFTP) to transfer files to the TE appliance and SSH to trigger
AV analysis via the temain command-line interface.

Files are processed sequentially to avoid overwhelming the appliance.
"""

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Optional

logger = logging.getLogger("te_scanner.main")

# AV file size limits
AV_FILE_SIZE_LIMIT = 2097152000  # ~2 GB — files >= this are skipped entirely


class AVHandler:
    """Handles AV fallback processing for files that cannot be scanned by TE.

    Opens a single SSH connection for the batch, transfers files via SFTP,
    triggers AV analysis via SSH command, parses results, and cleans up.

    Usage:
        with AVHandler(config) as handler:
            result = handler.process_file(file_info)
            # or
            results = handler.process_batch(file_infos)
    """

    def __init__(self, config):
        """Initialize AVHandler with configuration.

        Args:
            config: ScannerConfig object with AV settings
        """
        self.appliance_ip = config.appliance_ip
        self.ssh_username = config.ssh_username
        self.ssh_password = config.ssh_password
        self.av_remote_directory = config.av_remote_directory
        self.av_rule_id = config.av_rule_id if config.av_rule_id >= 1 else 1
        self._ssh_client = None
        self._sftp = None
        self._connected = False
        self._timeout_seconds = 1800  # 30 min per AV analysis command
        self._max_retries = 2
        self._retry_delay = 5

    def __enter__(self):
        """Context manager entry — open SSH connection."""
        self._connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit — close SSH connection."""
        self._disconnect()
        return False

    def _connect(self):
        """Establish SSH connection to the appliance.

        Raises:
            ImportError: If paramiko is not installed
            ConnectionError: If SSH connection fails
        """
        try:
            import paramiko
        except ImportError:
            raise ImportError(
                "paramiko is required for AV fallback. "
                "Install it with: pip install paramiko"
            )

        if self._connected:
            return

        try:
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._ssh_client.connect(
                hostname=self.appliance_ip,
                username=self.ssh_username,
                password=self.ssh_password,
                timeout=30,
            )
            self._sftp = self._ssh_client.open_sftp()
            self._connected = True
            logger.debug(f"SSH connection established to {self.appliance_ip}")
        except Exception as e:
            raise ConnectionError(
                f"Failed to connect to {self.appliance_ip} via SSH: {e}"
            )

    def _disconnect(self):
        """Close SSH and SFTP connections."""
        if self._sftp:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except Exception:
                pass
            self._ssh_client = None
        self._connected = False

    def _get_free_space(self) -> int:
        """Get available disk space on /var/log partition in bytes.

        Returns:
            Available space in bytes, or -1 on failure
        """
        if not self._connected:
            return -1
        try:
            stdin, stdout, stderr = self._ssh_client.exec_command(
                "df -k /var/log | tail -1"
            )
            output = stdout.read().decode("utf-8").strip()
            # Parse: Filesystem 1K-blocks Used Available Use% Mounted
            parts = output.split()
            if len(parts) >= 4:
                available_kb = int(parts[3])
                return available_kb * 1024
        except Exception as e:
            logger.warning(f"Failed to check disk space: {e}")
        return -1

    def _transfer_file(self, local_path: str, remote_name: str, file_size: int) -> bool:
        """Transfer a file to the remote appliance via SFTP.

        Args:
            local_path: Path to the local file
            remote_name: Filename on the remote appliance
            file_size: Size of the file in bytes (for disk space check)

        Returns:
            True if transfer succeeded, False otherwise
        """
        # Check disk space before transfer
        free_space = self._get_free_space()
        if free_space > 0:
            buffer_space = file_size * 1.1  # 10% buffer
            if free_space < file_size + buffer_space:
                logger.warning(
                    f"Insufficient disk space on appliance: "
                    f"need {file_size / (1024*1024):.0f} MB, {free_space / (1024*1024):.0f} MB available"
                )
                return False
            logger.debug(
                f"Disk space OK: {free_space / (1024*1024):.0f} MB available"
            )

        remote_path = f"{self.av_remote_directory}/{remote_name}"

        for attempt in range(self._max_retries):
            try:
                logger.debug(f"Transferring {remote_name} (attempt {attempt + 1})")
                self._sftp.put(local_path, remote_path)
                logger.info(f"File transferred: {remote_name}")
                return True
            except Exception as e:
                logger.warning(
                    f"Transfer attempt {attempt + 1} failed for {remote_name}: {e}"
                )
                if attempt < self._max_retries - 1:
                    import time
                    time.sleep(self._retry_delay)
                else:
                    logger.error(f"Transfer failed for {remote_name} after {self._max_retries} attempts")
                    return False

        return False

    def _run_av_analysis(self, remote_name: str) -> tuple:
        """Run AV analysis command on the appliance.

        Args:
            remote_name: The safe filename on the remote appliance

        Returns:
            Tuple of (output_string, exit_code)
        """
        remote_path = f"{self.av_remote_directory}/{remote_name}"
        command = (
            f"$FWDIR/teCurrentPack/temain te_add_file "
            f"-force_path_av -r={self.av_rule_id} -f={remote_path}"
        )

        for attempt in range(self._max_retries):
            try:
                logger.debug(
                    f"Running AV analysis for {remote_name} "
                    f"(attempt {attempt + 1})"
                )
                stdin, stdout, stderr = self._ssh_client.exec_command(
                    command, timeout=self._timeout_seconds
                )

                output = stdout.read().decode("utf-8", errors="replace")
                stderr_text = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()

                if output:
                    logger.debug(
                        f"AV analysis output for {remote_name}: {output.strip()[:500]}"
                    )
                if stderr_text:
                    logger.debug(
                        f"AV analysis stderr for {remote_name}: {stderr_text.strip()[:500]}"
                    )

                return (output, exit_code)

            except Exception as e:
                logger.warning(
                    f"AV analysis attempt {attempt + 1} failed for {remote_name}: {e}"
                )
                if attempt < self._max_retries - 1:
                    import time
                    time.sleep(self._retry_delay)
                else:
                    logger.error(
                        f"AV analysis failed for {remote_name} after "
                        f"{self._max_retries} attempts"
                    )
                    return ("", -1)

        return ("", -1)

    def _parse_verdict(self, output: str, exit_code: int) -> str:
        """Parse the AV command output to extract the verdict.

        Extracts the :action field from the S-expression response.
        Maps (drop) to Malicious, (accept) to Benign.

        Args:
            output: The stdout from the temain command
            exit_code: The exit code from the command

        Returns:
            Verdict string: 'Benign', 'Malicious', or 'Error'
        """
        if exit_code != 0:
            logger.warning(f"AV analysis exited with code {exit_code}")
            return "Error"

        if not output or not output.strip():
            logger.warning(f"AV analysis produced no output")
            return "Error"

        # Parse :action from S-expression
        action_match = re.search(r':action\s*\(\s*(\w+)\s*\)', output)
        if action_match:
            action = action_match.group(1).lower()
            if action == "drop":
                return "Malicious"
            elif action == "accept":
                return "Benign"
            else:
                logger.warning(
                    f"AV analysis returned unrecognized action: {action}"
                )
                return "Error"

        # Fallback: check text output for "Verdict: drop/accept"
        output_lower = output.lower()
        if "malicious" in output_lower:
            return "Malicious"
        elif "benign" in output_lower:
            return "Benign"

        logger.warning(
            f"Could not parse verdict from AV output. "
            f"No :action field found in S-expression."
        )
        return "Error"

    def _cleanup_remote(self, remote_name: str) -> None:
        """Remove the file from the remote appliance after analysis.

        Args:
            remote_name: The safe filename on the remote appliance
        """
        remote_path = f"{self.av_remote_directory}/{remote_name}"
        try:
            self._sftp.remove(remote_path)
            logger.debug(f"Remote file removed: {remote_name}")
        except Exception as e:
            logger.warning(f"Failed to remove remote file {remote_name}: {e}")

    def _sanitize_for_remote(self, filename: str) -> str:
        """Create a safe filename for the remote appliance.

        Only allows: ASCII letters (a-z, A-Z), digits (0-9), hyphens (-),
        underscores (_), and the original file extension.
        All other characters are replaced with underscores.

        Args:
            filename: The original filename

        Returns:
            A safe filename for remote use
        """
        from safe_filename import sanitize_for_remote as _sanitize
        return _sanitize(filename)

    def process_file(
        self,
        file_name: str,
        safe_file_name: str,
        sub_dir: str,
        full_path: str,
        zip_mgr=None,
    ) -> dict:
        """Process a single file through AV analysis.

        Full workflow: connect (if needed) -> transfer -> analyze -> parse verdict -> cleanup.

        Args:
            file_name: Original filename
            safe_file_name: ASCII-safe name (from sanitize_filename)
            sub_dir: Subdirectory relative to input directory
            full_path: Full local path to the file
            zip_mgr: ZipArchiveManager instance (for adding file to archive)

        Returns:
            Dict with keys: name, path, verdict, status, tex_status
        """
        # Get file size
        try:
            file_size = os.path.getsize(full_path)
        except OSError as e:
            logger.error(f"Cannot get file size for {file_name}: {e}")
            return {
                "name": file_name,
                "path": sub_dir if sub_dir else "",
                "verdict": "Error",
                "status": "error",
                "tex_status": None,
                "av_verdict": "Error",
            }

        # Check AV size limit
        if file_size >= AV_FILE_SIZE_LIMIT:
            logger.warning(
                f"File {file_name} ({file_size / (1024*1024*1024):.1f} GB) "
                f"exceeds AV limit (~2 GB). Skipping."
            )
            return {
                "name": file_name,
                "path": sub_dir if sub_dir else "",
                "verdict": "Error",
                "status": "error",
                "tex_status": None,
                "av_verdict": "Skipped_Above_AV_Limit",
            }

        # Get safe remote filename
        remote_name = self._sanitize_for_remote(file_name)
        logger.info(
            f"Processing {file_name} ({file_size / (1024*1024):.1f} MB) via AV "
            f"-> remote name: {remote_name}"
        )

        # Ensure we're connected
        if not self._connected:
            self._connect()

        # Transfer file
        if not self._transfer_file(full_path, remote_name, file_size):
            logger.error(
                f"AV transfer failed for {file_name} — file stays in input"
            )
            return {
                "name": file_name,
                "path": sub_dir if sub_dir else "",
                "verdict": "Error",
                "status": "error",
                "tex_status": None,
                "av_verdict": "Transfer_Failed",
            }

        # Run AV analysis
        output, exit_code = self._run_av_analysis(remote_name)
        verdict = self._parse_verdict(output, exit_code)

        logger.info(
            f"AV verdict for {file_name}: {verdict}"
        )

        # Clean up remote file
        self._cleanup_remote(remote_name)

        return {
            "name": file_name,
            "path": sub_dir if sub_dir else "",
            "verdict": verdict,
            "status": "success",
            "tex_status": None,
            "av_verdict": verdict,
        }

    def process_batch(self, file_infos: set) -> list:
        """Process a batch of files sequentially via AV.

        Args:
            file_infos: Set of (file_name, safe_file_name, sub_dir, full_path) tuples

        Returns:
            List of result dicts from process_file()
        """
        results = []
        for file_info in file_infos:
            file_name, safe_file_name, sub_dir, full_path = file_info
            try:
                result = self.process_file(
                    file_name, safe_file_name, sub_dir, full_path
                )
                results.append(result)
            except Exception as e:
                logger.error(
                    f"Unexpected error processing {file_name} via AV: {e}"
                )
                results.append({
                    "name": file_name,
                    "path": sub_dir if sub_dir else "",
                    "verdict": "Error",
                    "status": "error",
                    "tex_status": None,
                    "av_verdict": "Error",
                })
        return results

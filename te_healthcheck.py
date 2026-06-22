#!/usr/bin/env python3

"""
te_healthcheck.py v13.0 (alpha)
Health check module for TE API Scanner.

Verifies TE API functionality by uploading and querying a test file,
and optionally tests AV fallback path via SSH/SFTP.
Sends notification emails on failure or recovery.
"""

import json
import os
import re
import time
import logging
import hashlib
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("te_scanner.healthcheck")

# Health check timeout (seconds)
HEALTHCHECK_TIMEOUT = 60
# Polling interval for TE query during health check (seconds)
HEALTHCHECK_POLL_INTERVAL = 2


def check_te_health(config, healthcheck_dir: Optional[Path] = None) -> dict:
    """Check TE API health by uploading and querying a test file.

    Uploads eicar.com to the TE API, then polls for its result.
    Verifies the verdict is "Malicious" (EICAR test file).

    Args:
        config: ScannerConfig object
        healthcheck_dir: Path to healthcheck directory (defaults to app dir/healthcheck)

    Returns:
        Dict with keys: te, healthy, timestamp, message
    """
    if healthcheck_dir is None:
        healthcheck_dir = Path("healthcheck")

    test_file = healthcheck_dir / "eicar.com"

    if not test_file.exists():
        error_msg = f"Health check test file not found: {test_file}"
        logger.error(error_msg)
        return {
            "te": f"FAIL: {error_msg}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    url = f"https://{config.appliance_ip}:18194/tecloud/api/v1/file/"
    skip_tls = config.appliance_skip_tls_verify

    # Calculate SHA1
    sha1 = hashlib.sha1()
    try:
        with open(str(test_file), "rb") as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                sha1.update(block)
        sha1_hex = sha1.hexdigest()
        logger.info(f"Health check: SHA1 = {sha1_hex}")
    except Exception as e:
        error_msg = f"Failed to read test file: {e}"
        logger.error(error_msg)
        return {
            "te": f"FAIL: {error_msg}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    # Build request template (minimal, for health check)
    request = {
        "request": [
            {
                "features": ["te", "te_eb"],
                "te": {
                    "reports": ["summary"],
                    "reports_version_number": 2,
                    "return_errors": True,
                    "version_info": True,
                },
            }
        ]
    }
    data = json.dumps(request)

    # Upload file
    try:
        logger.info("Health check: Uploading test file to TE API...")
        with open(str(test_file), "rb") as f:
            curr_file = {"request": data, "file": f}
            response = requests.post(
                url=url + "upload",
                files=curr_file,
                verify=not skip_tls,
                timeout=30,
            )
        response_json = response.json()
        try:
            upload_status = response_json["response"][0]["status"]["label"]
        except (KeyError, IndexError):
            upload_status = "UNKNOWN"
        logger.info(f"Health check: Upload status = {upload_status}")

        if upload_status != "upload_success":
            error_msg = f"Upload returned unexpected status: {upload_status}"
            logger.error(f"Health check failed: {error_msg}")
            return {
                "te": f"FAIL: {error_msg}",
                "healthy": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": error_msg,
            }

    except Exception as e:
        error_msg = f"Upload failed: {e}"
        logger.error(f"Health check failed: {error_msg}")
        return {
            "te": f"FAIL: {error_msg}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    # Query for results
    query_request = {
        "request": [
            {
                "features": ["te", "te_eb"],
                "te": {
                    "reports": ["summary"],
                    "reports_version_number": 2,
                    "return_errors": True,
                    "version_info": True,
                },
                "sha1": sha1_hex,
            }
        ]
    }
    query_data = json.dumps(query_request)

    start_time = time.time()
    verdict = None
    status_label = None

    while time.time() - start_time < HEALTHCHECK_TIMEOUT:
        try:
            response = requests.post(
                url=url + "query",
                data=query_data,
                verify=not skip_tls,
                timeout=30,
            )
            response_json = response.json()

            try:
                status_label = response_json["response"][0]["status"]["label"]
            except (KeyError, IndexError):
                status_label = "UNKNOWN"

            # Check for combined_verdict
            try:
                verdict = response_json["response"][0]["te"]["combined_verdict"]
            except (KeyError, IndexError):
                verdict = None

            logger.debug(
                f"Health check query: status={status_label}, verdict={verdict}"
            )

            if verdict == "Malicious":
                logger.info(
                    f"Health check passed: TE API returned Malicious verdict"
                )
                return {
                    "te": "OK",
                    "healthy": True,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "message": "TE API health check passed (Malicious verdict)",
                }

            # If we got a final status but not the expected verdict
            if status_label in ("PASS", "FAIL") and verdict is not None:
                error_msg = f"Unexpected verdict: {verdict} (expected Malicious)"
                logger.error(f"Health check failed: {error_msg}")
                return {
                    "te": f"FAIL: {error_msg}",
                    "healthy": False,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "message": error_msg,
                }

            time.sleep(HEALTHCHECK_POLL_INTERVAL)

        except Exception as e:
            logger.error(f"Health check query error: {e}")
            time.sleep(HEALTHCHECK_POLL_INTERVAL)

    # Timeout
    error_msg = (
        f"Health check timed out after {HEALTHCHECK_TIMEOUT}s "
        f"(status={status_label}, verdict={verdict})"
    )
    logger.error(f"Health check failed: {error_msg}")
    return {
        "te": f"FAIL: Timeout",
        "healthy": False,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": error_msg,
    }


def check_av_health(config, healthcheck_dir: Optional[Path] = None) -> dict:
    """Check AV fallback health by transferring and analyzing a test file.

    Connects to the appliance via SSH, transfers eicar.com.zip via SFTP,
    runs temain te_add_file, and parses the verdict.

    Args:
        config: ScannerConfig object
        healthcheck_dir: Path to healthcheck directory (defaults to app dir/healthcheck)

    Returns:
        Dict with keys: av, healthy, timestamp, message
    """
    if healthcheck_dir is None:
        healthcheck_dir = Path("healthcheck")

    test_file = healthcheck_dir / "eicar.com.zip"

    if not test_file.exists():
        error_msg = f"AV health check test file not found: {test_file}"
        logger.error(error_msg)
        return {
            "av": f"FAIL: {error_msg}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    # Import paramiko
    try:
        import paramiko
    except ImportError:
        error_msg = "paramiko not installed (required for AV health check)"
        logger.error(error_msg)
        return {
            "av": f"FAIL: {error_msg}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    # Connect via SSH
    ssh_client = None
    sftp = None
    try:
        logger.info("AV health check: Connecting to appliance via SSH...")
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname=config.appliance_ip,
            username=config.ssh_username,
            password=config.ssh_password,
            timeout=30,
        )
        sftp = ssh_client.open_sftp()
        logger.info("AV health check: SSH connection established")

        # Sanitize filename for remote
        remote_name = _sanitize_for_av_health(test_file.name)
        remote_path = f"{config.av_remote_directory}/{remote_name}"

        # Transfer file via SFTP
        logger.info(f"AV health check: Transferring test file to {remote_path}...")
        sftp.put(str(test_file), remote_path)
        logger.info(f"AV health check: File transferred: {remote_name}")

        # Run AV analysis command
        command = (
            f"$FWDIR/teCurrentPack/temain te_add_file "
            f"-force_path_av -r={config.av_rule_id if config.av_rule_id >= 1 else 1} "
            f"-f={remote_path}"
        )
        logger.info(f"AV health check: Running command: {command}")

        stdin, stdout, stderr = ssh_client.exec_command(
            command, timeout=HEALTHCHECK_TIMEOUT
        )

        output = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        logger.info(f"AV health check: exit_code={exit_code}")
        logger.info(f"AV health check: output length={len(output)}, stderr length={len(stderr_text)}")
        logger.info(f"AV health check: output='{output.strip()[:500]}'")
        if stderr_text.strip():
            logger.info(f"AV health check: stderr='{stderr_text.strip()[:500]}'")

        # Parse verdict
        verdict = _parse_av_verdict(output, exit_code, stderr_text)

        if verdict == "Malicious":
            logger.info("AV health check passed: Malicious verdict (drop)")
            result = {
                "av": "OK",
                "healthy": True,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": "AV health check passed (Malicious verdict)",
            }
        else:
            error_msg = f"AV health check: Unexpected verdict: {verdict} (expected Malicious)"
            logger.error(f"AV health check failed: {error_msg}")
            result = {
                "av": f"FAIL: {verdict}",
                "healthy": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "message": error_msg,
            }

        # Cleanup remote file
        try:
            sftp.remove(remote_path)
            logger.debug(f"AV health check: Cleaned up remote file")
        except Exception as e:
            logger.warning(f"AV health check: Failed to cleanup remote file: {e}")

        return result

    except Exception as e:
        error_msg = f"AV health check failed: {e}"
        logger.error(f"AV health check failed: {error_msg}")
        return {
            "av": f"FAIL: {str(e)}",
            "healthy": False,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": error_msg,
        }

    finally:
        if sftp:
            try:
                sftp.close()
            except Exception:
                pass
        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass


def _sanitize_for_av_health(filename: str) -> str:
    """Create a safe filename for the AV appliance.

    Only allows ASCII alphanumeric, hyphens, underscores, and the original extension.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    last_dot = filename.rfind(".")
    if last_dot > 0:
        base = filename[:last_dot]
        ext = filename[last_dot:]
    else:
        base = filename
        ext = ""

    safe_base = re.sub(r"[^a-zA-Z0-9_-]", "_", base)
    safe_base = re.sub(r"_+", "_", safe_base).strip("_")

    if not safe_base:
        import hashlib

        safe_base = hashlib.sha256(filename.encode("utf-8")).hexdigest()[:16]

    return f"{safe_base}{ext}"


def _parse_av_verdict(output: str, exit_code: int, stderr_text: str = "") -> str:
    """Parse the AV command output to extract the verdict.

    Args:
        output: stdout from the temain command
        exit_code: exit code from the command
        stderr_text: stderr from the temain command

    Returns:
        Verdict string: 'Malicious', 'Benign', or 'Error'
    """
    # Combine output and stderr for parsing
    combined = f"{output}\n{stderr_text}"

    if exit_code != 0:
        return "Error"

    if not combined or not combined.strip():
        return "Error"

    # Try to find verdict in output first, then stderr
    for source in [output, stderr_text]:
        if not source or not source.strip():
            continue

        source_lower = source.lower()

        # Parse :action from S-expression (with flexible spacing)
        action_match = re.search(r":action\s*\(\s*(\w+)\s*\)", source)
        if action_match:
            action = action_match.group(1).lower()
            if action == "drop":
                return "Malicious"
            elif action == "accept":
                return "Benign"
            else:
                logger.warning(f"AV verdict: unrecognized action: {action}")

        # Check for verdict keywords
        if "malicious" in source_lower or "drop" in source_lower:
            return "Malicious"
        elif "benign" in source_lower or "accept" in source_lower:
            return "Benign"

        # Check for action in parentheses
        action_match = re.search(r"\(\s*(drop|accept)\s*\)", source)
        if action_match:
            action = action_match.group(1).lower()
            if action == "drop":
                return "Malicious"
            elif action == "accept":
                return "Benign"

    return "Error"


def send_healthcheck_notification(
    config, result: dict, is_recovery: bool = False
) -> None:
    """Send a health check status email.

    Args:
        config: ScannerConfig with email settings
        result: Dict with keys: healthy, te, av, message, timestamp
        is_recovery: True if this is a recovery notification
    """
    if not config.email_enabled:
        logger.debug("Email not enabled, skipping health check notification")
        return

    if not config.email_smtp_server or not config.email_from or not config.email_to:
        logger.warning("Email not fully configured, skipping health check notification")
        return

    status = "HEALTHY" if result["healthy"] else "FAILED"
    if is_recovery:
        subject = f"TE Scanner: Health Check - {status} (API Recovered)"
    else:
        subject = f"TE Scanner: Health Check - {status}"

    timestamp = result.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines = [
        f"TE API Scanner Health Check - {status}",
        f"Timestamp: {timestamp}",
        "",
        f"TE: {result.get('te', 'N/A')}",
        f"AV:  {result.get('av', 'N/A')}",
        "",
        f"Details: {result.get('message', 'N/A')}",
    ]
    body = "\n".join(lines)

    logger.info(f"Sending health check notification: {subject}")

    try:
        import smtplib
        import ssl
        from email.header import Header
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import format_datetime

        msg = MIMEMultipart()
        msg["From"] = config.email_from
        msg["To"] = config.email_to
        msg["Subject"] = Header(subject, "utf-8")
        msg["Date"] = format_datetime(datetime.now().astimezone(), usegmt=False)
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if config.email_tls_method == "smtp_ssl":
            server = smtplib.SMTP_SSL(
                config.email_smtp_server,
                config.email_smtp_port,
                timeout=30,
            )
            server.ehlo()
            if config.email_username and config.email_password:
                server.login(config.email_username, config.email_password)
            server.sendmail(config.email_from, config.email_to, msg.as_string())
        else:
            with smtplib.SMTP(
                config.email_smtp_server,
                config.email_smtp_port,
                timeout=30,
            ) as server:
                server.ehlo()
                if config.email_tls_method == "starttls":
                    if getattr(config, "email_skip_tls_verify", False):
                        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                    else:
                        ssl_ctx = ssl.create_default_context()
                    server.starttls(context=ssl_ctx)
                    server.ehlo()
                if config.email_username and config.email_password:
                    server.login(config.email_username, config.email_password)
                server.sendmail(
                    config.email_from, config.email_to, msg.as_string()
                )

        logger.info(
            f"Health check notification sent to {config.email_to}: {subject}"
        )
    except Exception as e:
        logger.warning(f"Failed to send health check notification: {e}")

#!/usr/bin/env python3

"""
notification.py v11.2 (alpha)
Email notification system for TE API Scanner.
Sends batch completion notifications via SMTP with configurable templates
and optional IMAP "Sent" folder saving.
"""

import smtplib
import ssl
import logging
import imaplib
from email.header import Header
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from email.utils import format_datetime
from string import Template

_SCRIPT_DIR = Path(__file__).resolve().parent


def send_batch_notification(config, summary):
    """
    Send email notification after batch processing completes.

    Args:
        config: ScannerConfig with email settings
        summary: dict with keys: processed, benign, malicious, error,
                 malicious_files (list of dicts with 'name' and 'verdict'),
                 all_files (optional list of dicts with file details)
    """
    if not config.email_enabled:
        return

    if not config.email_smtp_server or not config.email_from or not config.email_to:
        logging.getLogger("te_scanner.notification").warning(
            "Email not configured: smtp_server, from, and to are required"
        )
        return

    logger = logging.getLogger("te_scanner.notification")

    try:
        # Build email content
        subject = _build_subject(config, summary)
        body = _build_email_body(config, summary)

        # Create message
        msg = MIMEMultipart()
        msg["From"] = config.email_from
        msg["To"] = config.email_to
        msg["Subject"] = subject
        msg["Date"] = format_datetime(datetime.now().astimezone(), usegmt=False)
        msg.attach(MIMEText(body, "plain"))

        # Send via SMTP
        logger.debug(
            f"Connecting to SMTP server {config.email_smtp_server}:{config.email_smtp_port}"
        )
        if config.email_tls_method == "smtp_ssl":
            # Implicit SSL from connection start (port 465)
            server = smtplib.SMTP_SSL(config.email_smtp_server, config.email_smtp_port, timeout=30)
            server.ehlo()
            if config.email_username and config.email_password:
                server.login(config.email_username, config.email_password)
            server.sendmail(config.email_from, config.email_to, msg.as_string())
        else:
            # STARTTLS or none (port 587 or similar)
            with smtplib.SMTP(config.email_smtp_server, config.email_smtp_port, timeout=30) as server:
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

                server.sendmail(config.email_from, config.email_to, msg.as_string())

        logger.info(f"Email notification sent to {config.email_to}: {subject}")

        # Save to IMAP "Sent" folder if enabled
        if config.email_imap_enabled:
            _save_to_imap(config, body, subject)

    except Exception as e:
        logger.warning(f"Failed to send email notification: {e}")


def _build_subject(config, summary):
    """Build the email subject, optionally using a template."""
    subject_template = getattr(config, "email_subject_template", None)

    if subject_template:
        try:
            t = Template(subject_template)
            safe_data = {
                "timestamp": datetime.now().astimezone().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "appliance_ip": config.appliance_ip or "N/A",
                "processed": summary.get("processed", 0),
                "benign": summary.get("benign", 0),
                "malicious": summary.get("malicious", 0),
                "error": summary.get("error", 0),
            }
            return t.safe_substitute(safe_data)
        except Exception as e:
            logging.getLogger("te_scanner.notification").warning(
                f"Failed to render subject template: {e}. Using default."
            )

    # Default subject
    return f"TE Scanner: {summary['processed']} files processed"


def _build_email_body(config, summary):
    """
    Build the email body text.

    Uses the configured template file if available, falling back to
    the legacy _build_legacy_body() if no template file is found.
    Template paths are resolved relative to the script directory.
    """
    template_file = (
        getattr(config, "email_template_file", None) or "data/email_template.txt"
    )

    # Resolve relative to script directory so it works regardless of CWD
    resolved = Path(template_file)
    if not resolved.is_absolute():
        resolved = _SCRIPT_DIR / resolved

    if resolved.is_file():
        return _render_template(str(resolved), config, summary)

    # Fallback to legacy behavior
    return _build_legacy_body(config, summary)


def _render_template(template_file, config, summary):
    """
    Load and render the email template from file.

    Uses string.Template with safe_substitute to handle missing placeholders.

    Args:
        template_file: Path to the template file
        config: ScannerConfig with email settings
        summary: dict with processing results

    Returns:
        str: Rendered template string
    """
    logger = logging.getLogger("te_scanner.notification")

    try:
        with open(template_file, "r") as f:
            template_str = f.read()
    except Exception as e:
        logger.warning(
            f"Failed to read template file '{template_file}': {e}. Using legacy body."
        )
        return _build_legacy_body(config, summary)

    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    # Build file list from all_files (if available)
    all_files = summary.get("all_files", [])
    file_list = _format_file_list(all_files) if all_files else ""

    # Build malicious files list
    malicious_files = ""
    malicious_list = summary.get("malicious_files", [])
    if malicious_list:
        lines = []
        for mf in malicious_list:
            lines.append(f"  - {mf['name']} (verdict: {mf['verdict']})")
        malicious_files = "\n".join(lines)

    error_count = summary.get("error", 0)
    if error_count > 0:
        error_note = (
            f"Note: {error_count} file(s) encountered errors during processing.\n"
            "Check logs for details.\n"
        )
    else:
        error_note = ""

    template_data = {
        "timestamp": timestamp,
        "appliance_ip": config.appliance_ip or "N/A",
        "processed": summary.get("processed", 0),
        "benign": summary.get("benign", 0),
        "malicious": summary.get("malicious", 0),
        "error": error_count,
        "file_list": file_list,
        "malicious_files": malicious_files,
        "error_note": error_note,
        "smtp_server": config.email_smtp_server or "N/A",
    }

    try:
        t = Template(template_str)
        return t.safe_substitute(template_data)
    except Exception as e:
        logger.warning(
            f"Failed to render template file '{template_file}': {e}. Using legacy body."
        )
        return _build_legacy_body(config, summary)


def _build_legacy_body(config, summary):
    """Legacy email body builder (fallback when no template file is configured)."""
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "TE API Scanner - Batch Report",
        "",
        f"Timestamp: {timestamp}",
        f"Appliance: {config.appliance_ip}",
        "",
        "Summary:",
        f"  Files processed:   {summary['processed']}",
        f"  Benign:            {summary['benign']}",
        f"  Malicious:         {summary['malicious']}",
        f"  Errors:            {summary['error']}",
        "",
    ]

    lines.append("File Details:")
    lines.append(_format_file_list(summary.get("all_files")))
    lines.append("")

    lines.append("Malicious Files:")
    if summary["malicious_files"]:
        for mf in summary["malicious_files"]:
            lines.append(f"  - {mf['name']} (verdict: {mf['verdict']})")
    else:
        lines.append("  (none)")
    lines.append("")

    if summary["error"] > 0:
        lines.append(
            f"Note: {summary['error']} file(s) encountered errors during processing."
        )
        lines.append("Check logs for details.")
        lines.append("")

    lines.append("---")
    lines.append(f"Server: {config.email_smtp_server}:{config.email_smtp_port}")

    return "\n".join(lines)


def _get_tex_status_message(tex_status):
    """
    Convert TEX status code to a human-readable message for email display.

    Returns:
        str: TEX status message, or empty string if TEX wasn't processed
    """
    if tex_status == "cleaned":
        return "removed parts"
    elif tex_status == "not_cleaned":
        return "didn't find anything to remove"
    elif tex_status == "unsupported":
        return "unsupported file type"
    else:
        return ""


def _format_file_list(all_files):
    """
    Render a file list for email display.

    Returns:
        str: Formatted file list lines joined by newlines, or empty string
    """
    if not all_files:
        return "(none)"
    lines = []
    for f in all_files:
        path = f.get("path")
        name = f.get("name", "unknown")
        verdict = f.get("verdict", "unknown")
        tex_status = f.get("tex_status")
        if path:
            file_display = f"{path}/{name}"
        else:
            file_display = name
        tex_msg = _get_tex_status_message(tex_status)
        if tex_msg:
            lines.append(f"  {file_display} - {verdict} and TEX {tex_msg}")
        else:
            lines.append(f"  {file_display} - {verdict}")
    return "\n".join(lines)


def _save_to_imap(config, body, subject):
    """
    Save the sent email to an IMAP 'Sent' folder.

    Uses IMAPPEND to store the raw message in the configured folder.
    Errors are logged as warnings and do not halt processing.

    Args:
        config: ScannerConfig with IMAP settings
        body: Plain text body string
        subject: Email subject string
    """
    logger = logging.getLogger("te_scanner.notification")

    if (
        not config.email_imap_server
        or not config.email_imap_username
        or not config.email_imap_password
    ):
        logger.debug(
            "IMAP sending enabled but credentials missing, skipping IMAP save."
        )
        return

    imap_server = config.email_imap_server
    imap_port = getattr(config, "email_imap_port", 993) or 993
    imap_use_ssl = getattr(config, "email_imap_use_ssl", True)
    imap_username = config.email_imap_username
    imap_password = config.email_imap_password
    imap_folder = getattr(config, "email_imap_folder", "Sent") or "Sent"

    try:
        if imap_use_ssl:
            if getattr(config, "email_imap_skip_tls_verify", False):
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            else:
                ssl_ctx = ssl.create_default_context()

            imap_conn = imaplib.IMAP4_SSL(
                imap_server, imap_port, ssl_context=ssl_ctx, timeout=30
            )
        else:
            imap_conn = imaplib.IMAP4(imap_server, imap_port, timeout=30)

        imap_conn.login(imap_username, imap_password)

        # Prepare the raw message for APPEND
        raw_lines = [
            "Subject: {}".format(Header(subject, "utf-8")),
            "From: {}".format(Header(config.email_from, "utf-8")),
            "To: {}".format(Header(config.email_to, "utf-8")),
            "Date: {}".format(format_datetime(datetime.now().astimezone(), usegmt=False)),
            "",
        ]
        raw_lines.append(body)
        raw_msg = "\r\n".join(raw_lines)

        # Append to the IMAP folder
        imap_conn.append(imap_folder, "()", None, raw_msg.encode("utf-8"))

        imap_conn.logout()

        logger.info(f"Email saved to IMAP folder '{imap_folder}' on {imap_server}")

    except Exception as e:
        logger.warning(f"Failed to save email to IMAP folder '{imap_folder}': {e}")

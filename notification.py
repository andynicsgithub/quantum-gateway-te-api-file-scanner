#!/usr/bin/env python3

"""
notification.py v9.1 (alpha)
Email notification system for TE API Scanner.
Sends batch completion notifications via SMTP.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone


def send_batch_notification(config, summary):
    """
    Send email notification after batch processing completes.
    
    Args:
        config: ScannerConfig with email settings
        summary: dict with keys: processed, benign, malicious, error,
                 malicious_files (list of dicts with 'name' and 'verdict')
    """
    if not config.email_enabled:
        return
    
    if not config.email_smtp_server or not config.email_from or not config.email_to:
        logging.getLogger('te_scanner.notification').warning(
            "Email not configured: smtp_server, from, and to are required"
        )
        return
    
    logger = logging.getLogger('te_scanner.notification')
    
    try:
        subject = f"TE Scanner: {summary['processed']} files processed"
        body = _build_email_body(config, summary, config.email_verbose)
        
        msg = MIMEMultipart()
        msg['From'] = config.email_from
        msg['To'] = config.email_to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(config.email_smtp_server, config.email_smtp_port)
        server.ehlo()
        
        if config.email_use_tls:
            server.starttls()
            server.ehlo()
        
        if config.email_username and config.email_password:
            server.login(config.email_username, config.email_password)
        
        server.sendmail(config.email_from, config.email_to, msg.as_string())
        server.quit()
        
        logger.info(f"Email notification sent to {config.email_to}: {subject}")
        
    except Exception as e:
        logger.warning(f"Failed to send email notification: {e}")


def _build_email_body(config, summary, verbose=False):
    """Build the email body text."""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    lines = [
        f'TE API Scanner - Batch Report',
        f'',
        f'Timestamp: {timestamp}',
        f'Appliance: {config.appliance_ip}',
        f'',
        f'Summary:',
        f'  Files processed:   {summary["processed"]}',
        f'  Benign:            {summary["benign"]}',
        f'  Malicious:         {summary["malicious"]}',
        f'  Errors:            {summary["error"]}',
        f'',
    ]
    
    if verbose:
        lines.append(f'File Details:')
        for f in summary.get('all_files', []):
            path = f['path']
            name = f['name']
            verdict = f['verdict']
            if path:
                file_display = f'{path}/{name}'
            else:
                file_display = name
            lines.append(f'  {file_display} - {verdict}')
        lines.append('')
    
    if summary['malicious_files']:
        lines.append(f'Malicious Files:')
        for mf in summary['malicious_files']:
            lines.append(f'  - {mf["name"]} (verdict: {mf["verdict"]})')
        lines.append('')
    
    if summary['error'] > 0:
        lines.append(f'Note: {summary["error"]} file(s) encountered errors during processing.')
        lines.append(f'Check logs for details.')
        lines.append('')
    
    lines.append('---')
    lines.append(f'Server: {config.email_smtp_server}:{config.email_smtp_port}')
    
    return '\n'.join(lines)

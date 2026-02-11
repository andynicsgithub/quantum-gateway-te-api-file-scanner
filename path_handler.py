#!/usr/bin/env python3

"""
path_handler.py
Cross-platform path handling utilities for TE API Scanner.
Handles local paths, Windows UNC paths, and Linux SMB mounts with retry logic.
"""

import os
import sys
import time
import shutil
import hashlib
from pathlib import Path, PureWindowsPath, PurePosixPath
from typing import Tuple, Optional


class PathHandler:
    """
    Centralized path handling with platform-specific support for:
    - Windows UNC paths (\\server\share)
    - Linux SMB mounts (/mnt/smbshare)
    - Cross-filesystem moves
    - Network path retry logic
    """
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows platform."""
        return sys.platform == 'win32'
    
    @staticmethod
    def normalize_path(path_str: str) -> Path:
        """
        Normalize path for current platform.
        Converts any path format to pathlib.Path with proper separators.
        
        Args:
            path_str: Path string in any format
            
        Returns:
            Normalized Path object
        """
        # Handle empty or None
        if not path_str:
            return Path('.')
        
        # Expand user home directory
        path_str = os.path.expanduser(path_str)
        
        # Expand environment variables
        path_str = os.path.expandvars(path_str)
        
        # Convert to Path and resolve
        path = Path(path_str)
        
        # Normalize the path (resolve . and .., fix separators)
        try:
            # Use resolve() cautiously - it requires path to exist
            # For non-existent paths, just normalize separators
            normalized = Path(os.path.normpath(path))
            return normalized
        except Exception:
            # If resolve fails, just return normalized version
            return Path(os.path.normpath(path))
    
    @staticmethod
    def is_unc_path(path: Path) -> bool:
        """
        Check if path is a Windows UNC path (\\server\share).
        
        Args:
            path: Path object to check
            
        Returns:
            True if UNC path, False otherwise
        """
        path_str = str(path)
        return path_str.startswith('\\\\') or path_str.startswith('//')
    
    @staticmethod
    def is_smb_path(path: Path) -> bool:
        """
        Detect if path is an SMB/network path.
        - Windows: UNC paths (\\server\share)
        - Linux: Common SMB mount points (/mnt, /media, /net)
        
        Args:
            path: Path object to check
            
        Returns:
            True if likely SMB/network path, False otherwise
        """
        # Windows UNC paths
        if PathHandler.is_unc_path(path):
            return True
        
        # Linux SMB mount detection (heuristic)
        if not PathHandler.is_windows():
            path_str = str(path)
            # Common Linux SMB mount points
            smb_indicators = ['/mnt/', '/media/', '/net/', '/smb/', '/cifs/']
            if any(path_str.startswith(indicator) for indicator in smb_indicators):
                return True
            
            # Check if path is on a network filesystem (if it exists)
            try:
                if path.exists():
                    # Try to detect CIFS/SMB filesystem
                    # This requires the path to exist
                    import subprocess
                    result = subprocess.run(
                        ['stat', '-f', '-c', '%T', str(path)],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.returncode == 0:
                        fs_type = result.stdout.strip().lower()
                        if 'cifs' in fs_type or 'smb' in fs_type or 'nfs' in fs_type:
                            return True
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                # If stat fails or times out, assume not SMB
                pass
        
        return False
    
    @staticmethod
    def validate_path(path: Path, create: bool = False, retry_count: int = 3) -> Tuple[bool, str]:
        """
        Validate path accessibility with retry logic for network paths.
        
        Args:
            path: Path to validate
            create: If True, create directory if it doesn't exist
            retry_count: Number of retry attempts for network paths
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        is_network = PathHandler.is_smb_path(path)
        wait_time = 2 if is_network else 0.5
        
        for attempt in range(retry_count):
            try:
                # Check if path exists
                exists = path.exists()
                
                if exists:
                    # Verify we can access it
                    if path.is_dir():
                        # Try to list directory
                        list(path.iterdir())
                        return True, f"Path {path} is accessible"
                    else:
                        return False, f"Path {path} exists but is not a directory"
                
                # Path doesn't exist
                if create:
                    # Try to create it
                    path.mkdir(parents=True, exist_ok=True)
                    return True, f"Created directory {path}"
                else:
                    return False, f"Path {path} does not exist"
                    
            except PermissionError as e:
                return False, f"Permission denied accessing {path}: {e}"
            
            except OSError as e:
                # Network paths may have transient errors
                if is_network and attempt < retry_count - 1:
                    time.sleep(wait_time)
                    wait_time *= 2  # Exponential backoff
                    continue
                return False, f"OS error accessing {path}: {e}"
            
            except Exception as e:
                if attempt < retry_count - 1:
                    time.sleep(wait_time)
                    continue
                return False, f"Error accessing {path}: {e}"
        
        return False, f"Failed to validate {path} after {retry_count} attempts"
    
    @staticmethod
    def safe_move(src: Path, dst: Path, verify_checksum: bool = None, retry_count: int = 3) -> Tuple[bool, str]:
        """
        Platform-aware file move with retry logic and optional verification.
        Handles:
        - Cross-filesystem moves (copy + delete)
        - Windows file locking
        - Network path latency
        - Checksum verification for network paths
        
        Args:
            src: Source file path
            dst: Destination file path
            verify_checksum: If True, verify SHA1 after move. Auto-enabled for SMB paths.
            retry_count: Number of retry attempts
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Auto-enable checksum verification for network paths
        if verify_checksum is None:
            verify_checksum = PathHandler.is_smb_path(src) or PathHandler.is_smb_path(dst)
        
        # Calculate source checksum if verification needed
        src_checksum = None
        if verify_checksum:
            try:
                src_checksum = PathHandler._calculate_sha1(src)
            except Exception as e:
                return False, f"Failed to calculate source checksum: {e}"
        
        # Ensure destination directory exists
        dst_parent = dst.parent
        try:
            dst_parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return False, f"Failed to create destination directory {dst_parent}: {e}"
        
        # Attempt move with retry logic
        wait_time = 1.0
        last_error = None
        
        for attempt in range(retry_count):
            try:
                # Use shutil.move for cross-filesystem support
                shutil.move(str(src), str(dst))
                
                # Verify checksum if required
                if verify_checksum and src_checksum:
                    dst_checksum = PathHandler._calculate_sha1(dst)
                    if src_checksum != dst_checksum:
                        # Checksum mismatch - delete corrupted destination
                        try:
                            dst.unlink()
                        except:
                            pass
                        return False, f"Checksum mismatch after move (corruption detected)"
                
                return True, f"Successfully moved {src.name} to {dst}"
                
            except PermissionError as e:
                # Windows file locking - retry
                last_error = f"Permission error (file may be locked): {e}"
                if attempt < retry_count - 1:
                    time.sleep(wait_time)
                    wait_time *= 2
                    continue
                    
            except FileNotFoundError as e:
                # Source disappeared
                return False, f"Source file not found: {e}"
                
            except OSError as e:
                # Various OS errors (network timeout, disk full, etc.)
                last_error = f"OS error: {e}"
                if attempt < retry_count - 1:
                    time.sleep(wait_time)
                    wait_time *= 2
                    continue
                    
            except Exception as e:
                # Unexpected errors
                last_error = f"Unexpected error: {e}"
                if attempt < retry_count - 1:
                    time.sleep(wait_time)
                    wait_time *= 2
                    continue
        
        return False, f"Failed to move file after {retry_count} attempts: {last_error}"
    
    @staticmethod
    def _calculate_sha1(file_path: Path) -> str:
        """
        Calculate SHA1 hash of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA1 hash as hexadecimal string
        """
        sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            while True:
                block = f.read(2 ** 10)  # 1KB blocks
                if not block:
                    break
                sha1.update(block)
        return sha1.hexdigest()
    
    @staticmethod
    def supports_long_paths() -> bool:
        """
        Check if Windows long path support is enabled (>260 characters).
        
        Returns:
            True if long paths supported or not on Windows, False if disabled
        """
        if not PathHandler.is_windows():
            return True  # Not applicable on non-Windows
        
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\FileSystem',
                0,
                winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, 'LongPathsEnabled')
            winreg.CloseKey(key)
            return value == 1
        except:
            return False

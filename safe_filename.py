#!/usr/bin/env python3

"""
safe_filename.py
Utilities for handling filenames that may contain non-UTF-8 characters.

The TE API server only accepts UTF-8 filenames. This module provides
a sanitize_filename() function that:

1. Replaces non-UTF-8 bytes with '_'
2. Preserves the original file extension
3. If the cleaned name is empty, uses a full SHA256 hash of the original
   filename as the base
4. If the cleaned name collides with a previously seen name, appends the
   full SHA256 hash (prepended by '_') to guarantee uniqueness

All collision checking is done via a shared 'seen' dict passed by the caller.
"""

import hashlib


def sanitize_filename(filename: str, seen: dict) -> str:
    """Return a UTF-8-safe filename.

    The filename is cleaned in-place by replacing any byte that cannot
    be represented in UTF-8 with an underscore ('_').  The original file
    extension is always preserved.

    When the cleaned name is empty or collides with a name already
    recorded in *seen*, the full SHA-256 hash of the original filename
    (64 hex characters) is appended using an underscore separator.

    Args:
        filename: The original filename (may contain non-UTF-8 bytes).
        seen:     A dict mapping cleaned names to the original name.
                  This dict is mutated to track uniqueness.

    Returns:
        A filename guaranteed to be valid UTF-8, unique within the
        lifetime of the *seen* dict, and sharing the original extension.
    """
    # ------------------------------------------------------------------
    # 1. Extract extension before any transformation
    # ------------------------------------------------------------------
    last_dot = filename.rfind('.')
    if last_dot > 0:
        base = filename[:last_dot]
        ext = filename[last_dot:]  # includes the dot
    else:
        base = filename
        ext = ''

    # ------------------------------------------------------------------
    # 2. Replace non-UTF-8 bytes with '_' in the base portion only
    # ------------------------------------------------------------------
    # On Linux, os.fsdecode() uses surrogateescape, producing surrogates
    # for bytes that can't decode as UTF-8. Encode back to bytes first,
    # then decode with 'replace' to get the replacement character, then
    # replace that with '_'.
    raw_base_bytes = base.encode('utf-8', errors='surrogateescape')
    cleaned_base = raw_base_bytes.decode('utf-8', errors='replace').replace('\ufffd', '_')

    # If base was entirely non-UTF-8 it may now be all underscores.
    # Treat a name consisting only of '_' as "empty".
    stripped = cleaned_base.strip('_')

    # ------------------------------------------------------------------
    # 3. Compute SHA-256 of the original filename bytes
    # ------------------------------------------------------------------
    hash_hex = hashlib.sha256(filename.encode('utf-8', errors='replace')).hexdigest()

    # ------------------------------------------------------------------
    # 4. Build candidate and check for collisions / emptiness
    # ------------------------------------------------------------------
    if not stripped:
        # All bytes were non-UTF-8 → use hash as the entire base
        candidate = f"{hash_hex}{ext}"
    else:
        candidate = f"{cleaned_base}{ext}"

    # Check collision — append hash if already seen
    if candidate in seen:
        candidate = f"{cleaned_base}_{hash_hex}{ext}"

    # Record in seen (first occurrence wins)
    if candidate not in seen:
        seen[candidate] = filename

    return candidate

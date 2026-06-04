#!/usr/bin/env python3

"""
safe_filename.py v11.2 (alpha)
Utilities for generating ASCII-only pseudonyms from filenames.

The TE API server only accepts filenames composed of ASCII characters.
This module provides a sanitize_filename() function that:

1. Converts the filename to ASCII by replacing any non-ASCII character
   with an underscore ('_')
2. Preserves the original file extension
3. If the cleaned name is empty (or becomes all underscores after
   stripping), uses a full SHA256 hash of the original filename as
   the entire base
4. If the cleaned name collides with a previously seen name, appends
   the full SHA256 hash (prepended by '_') to guarantee uniqueness

All collision checking is done via a shared 'seen' dict passed by
the caller.
"""

import hashlib


def sanitize_filename(filename: str, seen: dict) -> str:
    """Return an ASCII-only filename derived from the original.

    Every byte in the filename that falls outside the ASCII range
    (0x00–0x7F) is replaced with an underscore ('_').  The original
    file extension is preserved unchanged.

    When the cleaned name is empty (or consists only of underscores
    after stripping) or collides with a name already recorded in
    *seen*, the full SHA-256 hash of the original filename (64 hex
    characters) is used — as the entire base when empty, or
    appended with an underscore separator on collision.

    Args:
        filename: The original filename (may contain non-ASCII bytes).
        seen:     A dict mapping cleaned names to the original name.
                  This dict is mutated to track uniqueness.

    Returns:
        An ASCII-only filename, unique within the lifetime of the
        *seen* dict, and sharing the original extension.
    """
    # ------------------------------------------------------------------
    # 1. Extract extension before any transformation
    # ------------------------------------------------------------------
    last_dot = filename.rfind(".")
    if last_dot > 0:
        base = filename[:last_dot]
        ext = filename[last_dot:]  # includes the dot
    else:
        base = filename
        ext = ""

    # ------------------------------------------------------------------
    # 2. Convert base to ASCII-only by replacing every non-ASCII char
    # ------------------------------------------------------------------
    # On Linux, os.fsdecode() uses surrogateescape, producing surrogates
    # for bytes that can't decode as any Unicode character.  Encode back
    # to raw bytes first, then decode as ASCII with 'replace'.  Python's
    # 'replace' produces U+FFFD (�), so replace that with '_'.
    raw_base_bytes = base.encode("utf-8", errors="surrogateescape")
    cleaned_base = raw_base_bytes.decode("ascii", errors="replace").replace(
        "\ufffd", "_"
    )

    # If base was entirely non-ASCII it may now be all underscores.
    # Treat a name consisting only of '_' as "empty".
    stripped = cleaned_base.strip("_")

    # ------------------------------------------------------------------
    # 3. Compute SHA-256 of the original filename bytes
    # ------------------------------------------------------------------
    hash_hex = hashlib.sha256(
        filename.encode("utf-8", errors="surrogateescape")
    ).hexdigest()

    # ------------------------------------------------------------------
    # 4. Build candidate and check for collisions / emptiness
    # ------------------------------------------------------------------
    if not stripped:
        # All bytes were non-ASCII → use hash as the entire base
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

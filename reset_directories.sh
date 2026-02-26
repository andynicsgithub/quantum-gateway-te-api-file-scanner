#!/bin/bash
#
# reset_directories.sh - Bash script to reset directories based on config.ini
# Moves files from benign/quarantine/error back to input preserving structure
# Empties reports directory completely. No logging, prints operations and summary.
#
# Usage: ./reset_directories.sh [config_file]
#

set -e

CONFIG_FILE="${1:-config.ini}"

# Function to read INI file and output key=value pairs
read_ini() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "Error: Config file not found: $file" >&2
        exit 1
    fi

    while IFS='=' read -r key value; do
        [[ -z "$key" ]] && continue

        # Skip comments
        [[ "$key" =~ ^[[:space:]]*[#\;] ]] && continue

        # Skip section headers
        [[ "$key" =~ ^\[.*\]$ ]] && continue

        # Trim whitespace
        key="${key// /}"
        value="${value// /}"

        [[ -z "$key" ]] && continue

        echo "config_${key}=${value}"
    done < "$file"
}

# Expand ~ and environment variables in a path
expand_path() {
    local path="$1"
    [[ -z "$path" ]] && return
    path="${path/#\~/$HOME}"
    path="${path//\$HOME/$HOME}"
    path="${path//\$USER/$USER}"
    path="${path//\$PWD/$PWD}"
    echo "$path"
}

# Move files from src to dst preserving directory structure, returns count
move_with_structure() {
    local src="$1"
    local dst="$2"
    local count=0

    if [[ ! -d "$src" ]]; then
        return 0
    fi

    while IFS= read -r -d '' file; do
        local rel="${file#"$src"/}"
        local dest_dir="$dst/${rel%/*}"
        mkdir -p "$dest_dir"
        mv -f "$file" "$dest_dir/${rel##*/}"
        echo "Moved $rel"
        ((count++)) || true
    done < <(find "$src" -type f -print0)

    echo "$count"
}

# Remove all files and empty dirs under a directory, returns count
clear_directory() {
    local dir="$1"
    local count=0

    if [[ ! -d "$dir" ]]; then
        echo 0
        return 0
    fi

    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++)) || true
    done < <(find "$dir" -type f -print0 2>/dev/null)

    echo "$count"
}

# Remove empty subdirectories from a directory
remove_empty_dirs() {
    local dir="$1"
    [[ ! -d "$dir" ]] && return
    find "$dir" -mindepth 1 -type d -empty -delete 2>/dev/null || true
}

# --- Main ---

echo "Configuration:"
echo "  Config file: $CONFIG_FILE"
echo ""

# Source the parsed INI values into the current shell
eval "$(read_ini "$CONFIG_FILE")"

input=$(expand_path "$config_input_directory")
benign=$(expand_path "$config_benign_directory")
quarantine=$(expand_path "$config_quarantine_directory")
error=$(expand_path "$config_error_directory")
reports=$(expand_path "$config_reports_directory")

echo "  input:       $input"
echo "  benign:      $benign"
echo "  quarantine:  $quarantine"
echo "  error:       $error"
echo "  reports:     $reports"
echo ""

echo "Actions to be performed:"
echo "  * Move all files from benign/quarantine/error into input (keeping folder structure)."
echo "  * Completely empty the reports directory."
echo ""

read -rp "Proceed with these actions? (yes/no): " response
if [[ "$response" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

echo ""

total_moved=0
total_moved=$(( total_moved + $(move_with_structure "$benign"     "$input") ))
remove_empty_dirs "$benign"
total_moved=$(( total_moved + $(move_with_structure "$quarantine" "$input") ))
remove_empty_dirs "$quarantine"
total_moved=$(( total_moved + $(move_with_structure "$error"      "$input") ))
remove_empty_dirs "$error"

echo ""
echo "Moved a total of $total_moved files into $input"
echo ""

removed=$(clear_directory "$reports")
echo "Removed $removed items from reports directory"

echo ""
echo "Done."

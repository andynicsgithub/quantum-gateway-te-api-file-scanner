#!/bin/bash
#
# reset_directories.sh - Bash script to reset directories based on config.ini
# Moves files from benign/quarantine/error back to input preserving structure
# Empties reports, tex_clean_files, and zip_archive directories completely.
# No logging, prints operations and summary.
#
# Usage: ./reset_directories.sh [config_file]
#

set -e

CONFIG_FILE="${1:-config.ini}"

# Read INI values from [DEFAULT] and [TEX] sections only, output as quoted key=value
read_ini() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "Error: Config file not found: $file" >&2
        exit 1
    fi

    local in_default=false
    local in_tex=false

    while IFS= read -r raw_line; do
        # Remove carriage returns (Windows line endings)
        raw_line="${raw_line//$'\r'/}"

        # Remove leading/trailing whitespace
        local line="${raw_line#"${raw_line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"

        [[ -z "$line" ]] && continue

        # Skip comments
        [[ "$line" =~ ^[#\;] ]] && continue

        # Section header
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            if [[ "$line" == "[DEFAULT]" ]]; then
                in_default=true
                in_tex=false
            elif [[ "$line" == "[TEX]" ]]; then
                in_tex=true
                in_default=false
            else
                in_default=false
                in_tex=false
            fi
            continue
        fi

        # Only process lines from [DEFAULT] or [TEX]
        if [[ "$in_default" == true || "$in_tex" == true ]]; then
            # Split on first = only
            local key="${line%%=*}"
            local value="${line#*=}"

            # Trim whitespace
            key="${key#"${key%%[![:space:]]*}"}"
            key="${key%"${key##*[![:space:]]}"}"
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"

            [[ -z "$key" ]] && continue

            # Quote the value to handle special chars (=, /, #, etc.)
            echo "config_${key}='${value}'"
        fi
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
        echo "0"
        return 0
    fi

    while IFS= read -r -d '' file; do
        local rel="${file#"$src"/}"
        local dest_file="$dst/$rel"

        if [[ "$rel" == */* ]]; then
            local dest_dir="$dst/${rel%/*}"
            mkdir -p "$dest_dir"
            mv -f "$file" "$dest_dir/"
        else
            mv -f "$file" "$dst/"
        fi

        echo "Moved $rel" >&2
        ((count++)) || true
    done < <(find "$src" -type f -print0 2>/dev/null)

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

eval "$(read_ini "$CONFIG_FILE")"

input=$(expand_path "$config_input_directory")
benign=$(expand_path "$config_benign_directory")
quarantine=$(expand_path "$config_quarantine_directory")
error=$(expand_path "$config_error_directory")
reports=$(expand_path "$config_reports_directory")
tex_clean_files=$(expand_path "$config_tex_clean_files_directory")
zip_archive=$(expand_path "$config_zip_archive_directory")

echo "  input:              $input"
echo "  benign:             $benign"
echo "  quarantine:         $quarantine"
echo "  error:              $error"
echo "  reports:            $reports"
echo "  tex_clean_files:    $tex_clean_files"
echo "  zip_archive:        $zip_archive"
echo ""

echo "Actions to be performed:"
echo "  * Move all files from benign/quarantine/error into input (keeping folder structure)."
echo "  * Completely empty the reports directory."
echo "  * Completely empty the tex_clean_files directory."
echo "  * Completely empty the zip_archive directory (if configured)."
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

removed=$(clear_directory "$tex_clean_files")
echo "Removed $removed items from tex_clean_files directory"

if [[ -n "$zip_archive" ]]; then
    removed=$(clear_directory "$zip_archive")
    echo "Removed $removed items from zip_archive directory"
fi

echo ""
echo "Done."

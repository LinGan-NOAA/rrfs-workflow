#!/usr/bin/env python3
"""Build a Markdown summary of ShellCheck findings, checked files, excluded files, and inline line skips.

Location: .github/workflows/tools/bash_analysis_summary.py
Reads (any may be missing/empty):
  <dir>/shellcheck.checkstyle.xml       ShellCheck findings in Checkstyle XML format
  <dir>/excluded_files_from_list.txt    Configured rules and matched files from exclude_file_list_Bash.lst
  <dir>/inline_skipped_directives.txt   file:line:directive records for # ci-skip, # ci-ignore, # shellcheck disable
  <dir>/nco_bash_ci_audit.log           Full line-by-line execution log of checked files, skipped files, and skipped lines
Writes the sanitized Markdown comment body to <out>.
Prints "1" to stdout if ShellCheck findings exist, else "0".
"""
# Import os module for file existence, file size, path joining, and environment variable lookups
import os
# Import sys module for reading positional CLI arguments
import sys
# Import ElementTree for safe standard-library XML parsing (immune to XXE entity expansion)
import xml.etree.ElementTree as ET

# Define HTML comment marker used to identify and update a single sticky PR comment in place
MARKER = "<!-- bash-code-analysis-summary -->"
# Define maximum table rows rendered per section to keep PR comments readable and compact
MAX_ROWS = 50


def parse_checkstyle(path):
    """Parse ShellCheck checkstyle XML safely without executing or interpolating untrusted values."""
    # Initialize list to store parsed finding dictionaries
    rows = []
    # Return empty list immediately if XML file does not exist or has zero bytes
    if not (os.path.exists(path) and os.path.getsize(path) > 0):
        return rows
    try:
        # Parse XML document root using ElementTree
        root = ET.parse(path).getroot()
    except ET.ParseError:
        # Return empty list gracefully if XML is malformed or truncated
        return rows
    # Iterate over each <file> node in the Checkstyle XML report
    for f in root.findall("file"):
        # Retrieve file path attribute
        name = f.get("name", "")
        # Normalize leading ./ prefix for clean repository-relative display
        if name.startswith("./"):
            name = name[2:]
        # Iterate over each <error> child node inside the file
        for e in f.findall("error"):
            # Append structured finding record to result list
            rows.append({
                "file": name,
                "line": e.get("line", ""),
                "col": e.get("column", ""),
                "severity": e.get("severity", ""),
                "message": e.get("message", ""),
                "source": e.get("source", ""),
            })
    # Return all parsed ShellCheck findings
    return rows


def md_cell(text):
    """Neutralize characters that could break Markdown table cells or inject formatting."""
    # Convert None to empty string and coerce non-string inputs to str
    text = "" if text is None else str(text)
    # Escape pipe delimiters, replace CR/LF with spaces, and strip outer whitespace
    return (
        text.replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def read_excluded_entries(path):
    """Read configured rules and matched files from excluded_files_from_list.txt."""
    # Initialize list for raw patterns read from exclude_file_list_Bash.lst
    configured = []
    # Initialize list for repository files skipped due to matching an exclusion rule
    matched = []
    # Return empty lists if audit file is missing or empty
    if not (os.path.exists(path) and os.path.getsize(path) > 0):
        return configured, matched
    # Open audit file with UTF-8 replacement decoding for safety
    with open(path, "r", errors="replace") as fh:
        # Process file line by line
        for raw in fh:
            # Strip surrounding whitespace
            line = raw.strip()
            # Skip blank lines
            if not line:
                continue
            # Separate matched file entries from configured rule entries
            if line.startswith("MATCHED_FILE: "):
                matched.append(line[len("MATCHED_FILE: "):])
            else:
                configured.append(line)
    # Return both lists
    return configured, matched


def read_inline_skips(path):
    """Read exact file:line:directive records from inline_skipped_directives.txt."""
    # Initialize list of inline skip dictionaries
    skips = []
    # Return empty list if inline skips audit file is missing or empty
    if not (os.path.exists(path) and os.path.getsize(path) > 0):
        return skips
    # Open inline skips file safely
    with open(path, "r", errors="replace") as fh:
        # Parse each file:line:directive line
        for raw in fh:
            # Trim outer whitespace
            line = raw.strip()
            # Ignore empty lines
            if not line:
                continue
            # Split into at most 3 parts (file, line number, directive comment)
            parts = line.split(":", 2)
            # Store valid 3-part records
            if len(parts) == 3:
                skips.append({"file": parts[0], "line": parts[1], "directive": parts[2]})
    # Return parsed inline skip entries
    return skips


def read_checked_files(audit_log_path):
    """Extract checked file records from nco_bash_ci_audit.log."""
    # Initialize list for checked file entries
    checked = []
    # Return empty list if audit log does not exist or is empty
    if not (os.path.exists(audit_log_path) and os.path.getsize(audit_log_path) > 0):
        return checked
    # Read audit log lines safely
    with open(audit_log_path, "r", errors="replace") as fh:
        # Scan for CHECKED_FILE entries
        for raw in fh:
            # Strip outer whitespace
            line = raw.strip()
            # Extract entries prefixed with CHECKED_FILE:
            if line.startswith("CHECKED_FILE: "):
                checked.append(line[len("CHECKED_FILE: "):])
    # Return checked file summary strings
    return checked


def main():
    """Generate Markdown summary comment from diagnostics and audit logs."""
    # Read diagnostics directory path from argv[1] (default current directory)
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    # Read output Markdown file path from argv[2] (default comment.md)
    out = sys.argv[2] if len(sys.argv) > 2 else "comment.md"
    # Read optional GitHub Actions run URL from environment
    run_url = os.environ.get("RUN_URL", "")

    # Parse ShellCheck XML findings
    sc = parse_checkstyle(os.path.join(d, "shellcheck.checkstyle.xml"))
    # Parse global exclusion rules and matched skipped files
    configured_excl, matched_excl = read_excluded_entries(os.path.join(d, "excluded_files_from_list.txt"))
    # Parse file:line inline skip directives
    inline_skips = read_inline_skips(os.path.join(d, "inline_skipped_directives.txt"))
    # Parse checked file entries from main audit log
    checked_files = read_checked_files(os.path.join(d, "nco_bash_ci_audit.log"))
    # Determine whether any ShellCheck findings exist
    has_findings = bool(sc)

    # Start Markdown output with sticky comment marker and heading
    lines = [MARKER, "## Bash code analysis", ""]

    # Format ShellCheck results table or clean pass badge
    if not has_findings:
        lines.append(":white_check_mark: **shellcheck** found no issues.")
    else:
        lines.append("### shellcheck &mdash; {} finding(s)".format(len(sc)))
        lines.append("")
        lines.append("| File | Line:Col | Severity | Rule | Message |")
        lines.append("| --- | --- | --- | --- | --- |")
        # Render up to MAX_ROWS ShellCheck findings
        for r in sc[:MAX_ROWS]:
            rule = r["source"].split(".")[-1] if r["source"] else ""
            lines.append("| `{}` | {}:{} | {} | {} | {} |".format(
                md_cell(r["file"]), md_cell(r["line"]), md_cell(r["col"]),
                md_cell(r["severity"]), md_cell(rule), md_cell(r["message"]),
            ))
        # Indicate truncation if findings exceed MAX_ROWS
        if len(sc) > MAX_ROWS:
            lines.append("")
            lines.append("_...and {} more. See the full run for details._".format(len(sc) - MAX_ROWS))
    lines.append("")

    # Render collapsible audit section showing checked files, excluded files, and skipped lines
    lines.append("### Checked files, excluded files, and inline line skips")
    lines.append("")
    lines.append("<details><summary>Checked ({}) | Excluded via list ({} rules, {} files) | Inline line skips ({})</summary>".format(
        len(checked_files), len(configured_excl), len(matched_excl), len(inline_skips)
    ))
    lines.append("")
    # List checked files and which rules ran on each
    if checked_files:
        lines.append("**Checked files:**")
        for c in checked_files[:MAX_ROWS]:
            lines.append("- `{}`".format(md_cell(c)))
        lines.append("")
    # List configured exclude_file_list_Bash.lst entries
    if configured_excl:
        lines.append("**Configured `exclude_file_list_Bash.lst` entries:**")
        for entry in configured_excl[:MAX_ROWS]:
            lines.append("- `{}`".format(md_cell(entry)))
        lines.append("")
    # List exact repository files skipped due to exclude_file_list_Bash.lst
    if matched_excl:
        lines.append("**Skipped files (matched `exclude_file_list_Bash.lst`):**")
        for m in matched_excl[:MAX_ROWS]:
            lines.append("- `{}`".format(md_cell(m)))
        lines.append("")
    # Render table of exact file:line inline skip directives
    if inline_skips:
        lines.append("**Skipped lines (`# ci-skip`, `# ci-ignore`, `# shellcheck disable`):**")
        lines.append("")
        lines.append("| File | Line | Directive |")
        lines.append("| --- | --- | --- |")
        for s in inline_skips[:MAX_ROWS]:
            lines.append("| `{}` | {} | `{}` |".format(
                md_cell(s["file"]), md_cell(s["line"]), md_cell(s["directive"])
            ))
        lines.append("")
    lines.append("</details>")
    lines.append("")

    # Append link to GitHub Actions workflow run if RUN_URL is provided
    if run_url:
        lines.append("")
        lines.append("[View the analysis run]({})".format(run_url))

    # Join lines and enforce GitHub's 65536-character PR comment limit
    body = "\n".join(lines) + "\n"
    if len(body) > 65000:
        body = body[:64000] + "\n_...comment truncated._\n"
    # Write final Markdown content to output file
    with open(out, "w") as fh:
        fh.write(body)
    # Print 1 if ShellCheck findings exist, else 0
    print("1" if has_findings else "0")


if __name__ == "__main__":
    # Invoke main entry point when executed as a script
    main()
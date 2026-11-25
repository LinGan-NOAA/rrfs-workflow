#!/usr/bin/env python3
"""Render a sanitized sticky PR summary comment from ci_artifact_bash.

Reads Checkstyle XML diagnostics (shellcheck.checkstyle.xml and
nco_conventions.checkstyle.xml), dedicated skip/exclusion audit files
(excluded_files_from_list.txt and inline_skipped_directives.txt), and the
centralized log (ci_artifact_bash.log). Enforces a strict 10 MB size ceiling
(CWE-770), escapes Markdown table cells, surfaces prominent skip alerts
(CWE-285), and caps output under GitHub's 65,536-character PR comment limit.
"""

import os
import sys
import xml.etree.ElementTree as ET

# Hidden HTML marker used to locate and update the single sticky PR comment.
SUMMARY_MARKER = "<!-- bash-code-analysis-summary -->"
# Maximum bytes permitted per untrusted artifact file (10 MB ceiling).
MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
# Maximum table rows rendered per section to keep PR comments readable.
MAX_ROWS = 50
# Maximum total character length to stay safely below GitHub's 65,536 limit.
MAX_COMMENT_CHARS = 65000


def _validate_file_size(path):
    """Ensure an artifact file exists and does not exceed MAX_ARTIFACT_BYTES.

    Args:
        path: Filesystem path to a file inside ci_artifact_bash.

    Returns:
        True if the file exists, is non-empty, and is within the size ceiling.

    Raises:
        ValueError: If the file exceeds MAX_ARTIFACT_BYTES.
    """
    # Return False immediately if the optional file is absent.
    if not os.path.isfile(path):
        return False
    # Measure exact byte length on disk before reading into memory.
    size = os.path.getsize(path)
    # Abort if an untrusted artifact exceeds the 10 MB safety ceiling.
    if size > MAX_ARTIFACT_BYTES:
        raise ValueError(
            f"Artifact {os.path.basename(path)} ({size} bytes) exceeds "
            f"MAX_ARTIFACT_BYTES ({MAX_ARTIFACT_BYTES})."
        )
    # Return True only when the file contains data to parse.
    return size > 0


def md_cell(text):
    """Escape pipe characters and strip newlines for safe Markdown table cells.

    Args:
        text: Raw diagnostic message, file path, or directive string.

    Returns:
        Single-line string safe for embedding inside a Markdown table cell.
    """
    # Convert non-string values safely to string.
    raw = "" if text is None else str(text)
    # Strip carriage returns and replace newlines with spaces.
    cleaned = raw.replace("\r", "").replace("\n", " ").strip()
    # Escape Markdown pipe delimiters to prevent table column injection.
    return cleaned.replace("|", "\\|")


def parse_checkstyle(path):
    """Parse a Checkstyle XML file safely using xml.etree.ElementTree.

    Args:
        path: Path to a *.checkstyle.xml file inside ci_artifact_bash.

    Returns:
        List of finding dicts containing file, line, column, severity,
        source, and message keys.
    """
    # Return an empty list if the XML file is missing or empty.
    if not _validate_file_size(path):
        return []
    # Parse XML with standard ElementTree (immune to external entity XXE).
    tree = ET.parse(path)
    root = tree.getroot()
    findings = []
    # Iterate over every <file> element in the Checkstyle report.
    for file_el in root.findall("file"):
        fname = file_el.attrib.get("name", "")
        # Normalize leading ./ prefix for clean display in PR tables.
        if fname.startswith("./"):
            fname = fname[2:]
        # Extract each <error> child element under the file node.
        for err_el in file_el.findall("error"):
            findings.append(
                {
                    "file": fname,
                    "line": err_el.attrib.get("line", "0"),
                    "column": err_el.attrib.get("column", "0"),
                    "severity": err_el.attrib.get("severity", "warning"),
                    "source": err_el.attrib.get("source", "shellcheck"),
                    "message": err_el.attrib.get("message", ""),
                }
            )
    return findings


def read_excluded_entries(path):
    """Read configured exclusion rules and matched files from dedicated file.

    Args:
        path: Path to excluded_files_from_list.txt.

    Returns:
        Tuple of (rules_list, matched_files_list).
    """
    # Return empty lists when the exclusion log is absent or empty.
    if not _validate_file_size(path):
        return [], []
    rules = []
    matched = []
    # Read lines safely using UTF-8 with replacement for malformed bytes.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            # Separate matched file records from configured .lst patterns.
            if text.startswith("MATCHED_FILE: "):
                matched.append(text[len("MATCHED_FILE: "):])
            else:
                rules.append(text)
    return rules, matched


def read_inline_skips(path):
    """Read file:line:directive inline skip records from dedicated file.

    Args:
        path: Path to inline_skipped_directives.txt.

    Returns:
        List of (file_path, line_num, directive_text) tuples.
    """
    # Return an empty list when no inline skips were recorded.
    if not _validate_file_size(path):
        return []
    skips = []
    # Parse each colon-delimited file:line:directive entry.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            parts = text.split(":", 2)
            if len(parts) == 3:
                skips.append((parts[0], parts[1], parts[2]))
    return skips


def parse_central_log(path):
    """Extract checked files, skipped files, global skips, and failures.

    Args:
        path: Path to centralized ci_artifact_bash.log.

    Returns:
        Dict with checked, skipped_files, global_skips, and failures lists.
    """
    data = {
        "checked": [],
        "skipped_files": [],
        "global_skips": [],
        "failures": [],
    }
    # Return empty collections if ci_artifact_bash.log is absent or empty.
    if not _validate_file_size(path):
        return data
    # Classify structured log prefixes in a single streaming pass.
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            if text.startswith("CHECKED_FILE: "):
                data["checked"].append(text[len("CHECKED_FILE: "):])
            elif text.startswith("SKIPPED_FILE: "):
                data["skipped_files"].append(text[len("SKIPPED_FILE: "):])
            elif text.startswith("GLOBAL_SKIP: "):
                data["global_skips"].append(text[len("GLOBAL_SKIP: "):])
            elif text.startswith("FAIL ("):
                data["failures"].append(text)
    return data


def build_comment(art_dir, run_url=""):
    """Construct the complete sanitized Markdown PR summary comment.

    Args:
        art_dir: Directory containing downloaded ci_artifact_bash files.
        run_url: Optional URL to the analyzer GitHub Actions run.

    Returns:
        Tuple of (markdown_text, has_findings_bool).
    """
    # Parse both Checkstyle XML files inside ci_artifact_bash.
    sc_findings = parse_checkstyle(
        os.path.join(art_dir, "shellcheck.checkstyle.xml")
    )
    nco_findings = parse_checkstyle(
        os.path.join(art_dir, "nco_conventions.checkstyle.xml")
    )
    all_findings = sc_findings + nco_findings
    # Read dedicated exclusion and inline skip files kept in ci_artifact_bash.
    rules, matched_excl = read_excluded_entries(
        os.path.join(art_dir, "excluded_files_from_list.txt")
    )
    inline_skips = read_inline_skips(
        os.path.join(art_dir, "inline_skipped_directives.txt")
    )
    # Read checked files, skipped files, global skips, and failures from log.
    log_data = parse_central_log(
        os.path.join(art_dir, "ci_artifact_bash.log")
    )
    checked = log_data["checked"]
    skipped_files = log_data["skipped_files"]
    global_skips = log_data["global_skips"]
    failures = log_data["failures"]
    has_findings = bool(all_findings or failures)
    # Start comment with hidden sticky marker and title heading.
    lines = [SUMMARY_MARKER, "## NCO Consistency Bash Analysis", ""]
    # Render prominent uncollapsed security/audit warning if skips exist.
    if inline_skips or global_skips or matched_excl or skipped_files:
        lines.append(
            f"> :warning: **Audit Alert:** {len(global_skips)} global "
            f"override(s), {len(skipped_files)} skipped file(s), and "
            f"{len(inline_skips)} inline skip directive(s) were detected. "
            "Review the audit details below."
        )
        lines.append("")
    # Render pass/fail status banner and findings table.
    if not has_findings:
        lines.append(
            ":white_check_mark: **ShellCheck** and **NCO Bash conventions** "
            "found no issues."
        )
    else:
        lines.append(
            f":x: Found **{len(sc_findings)}** ShellCheck finding(s) and "
            f"**{len(nco_findings)}** NCO convention/security finding(s)."
        )
        if all_findings:
            lines.append("")
            lines.append("### Findings")
            lines.append("| File | Line | Severity | Rule | Message |")
            lines.append("| --- | --- | --- | --- | --- |")
            for item in all_findings[:MAX_ROWS]:
                lines.append(
                    f"| `{md_cell(item['file'])}` | {md_cell(item['line'])} "
                    f"| {md_cell(item['severity'])} "
                    f"| `{md_cell(item['source'])}` "
                    f"| {md_cell(item['message'])} |"
                )
            if len(all_findings) > MAX_ROWS:
                extra = len(all_findings) - MAX_ROWS
                lines.append(
                    f"\n*Showing first {MAX_ROWS} of {len(all_findings)} "
                    f"findings ({extra} truncated).*"
                )
        elif failures:
            lines.append("")
            lines.append("### Execution Failures")
            for item in failures[:MAX_ROWS]:
                lines.append(f"- `{md_cell(item)}`")
    # Append collapsible audit section combining log + dedicated skip files.
    lines.append("")
    lines.append("### Checked Files, Exclusions & Inline Line Skips")
    summary_hdr = (
        f"Checked ({len(checked)}) | Excluded via list "
        f"({len(rules)} rules, {len(matched_excl)} matched) | "
        f"Skipped files ({len(skipped_files)}) | "
        f"Inline skips ({len(inline_skips)})"
    )
    lines.append(f"<details><summary>{summary_hdr}</summary>")
    lines.append("")
    lines.append("**Checked files:**")
    if checked:
        for entry in checked[:MAX_ROWS]:
            lines.append(f"- `{md_cell(entry)}`")
    else:
        lines.append("- *None*")
    lines.append("")
    lines.append(
        "**Configured exclusion rules (`excluded_files_from_list.txt`):**"
    )
    if rules:
        for entry in rules[:MAX_ROWS]:
            lines.append(f"- `{md_cell(entry)}`")
    else:
        lines.append("- *None*")
    lines.append("")
    lines.append("**Skipped files:**")
    if skipped_files:
        for entry in skipped_files[:MAX_ROWS]:
            lines.append(f"- `{md_cell(entry)}`")
    else:
        lines.append("- *None*")
    lines.append("")
    lines.append("**Skipped lines (`inline_skipped_directives.txt`):**")
    if inline_skips:
        lines.append("")
        lines.append("| File | Line | Directive |")
        lines.append("| --- | --- | --- |")
        for fpath, lnum, dtext in inline_skips[:MAX_ROWS]:
            lines.append(
                f"| `{md_cell(fpath)}` | {md_cell(lnum)} "
                f"| `{md_cell(dtext)}` |"
            )
    else:
        lines.append("- *None*")
    lines.append("")
    lines.append("</details>")
    # Append workflow run link when provided via RUN_URL environment variable.
    if run_url:
        safe_url = md_cell(run_url)
        lines.append("")
        lines.append(
            f"[View full workflow run and ci_artifact_bash]({safe_url})"
        )
    # Assemble body and enforce GitHub's 65,000-character safety cap.
    body = "\n".join(lines) + "\n"
    if len(body) > MAX_COMMENT_CHARS:
        notice = "\n\n*Comment truncated to fit GitHub length limit.*\n"
        body = body[: MAX_COMMENT_CHARS - len(notice)] + notice
    return body, has_findings


def main(argv=None):
    """CLI entrypoint: generate PR comment file and print '1' or '0'.

    Args:
        argv: Optional list of CLI arguments [art_dir, output_md_path].

    Returns:
        Exit code 0 on success, 2 on invalid arguments.
    """
    args = sys.argv[1:] if argv is None else argv
    # Require ci_artifact_bash directory and output Markdown path arguments.
    if len(args) != 2:
        sys.stderr.write(
            "Usage: linter_nco_consistency_bash_summary.py "
            "<ci_artifact_dir> <output_md>\n"
        )
        return 2
    art_dir, out_path = args[0], args[1]
    run_url = os.environ.get("RUN_URL", "")
    # Generate sanitized Markdown body and finding indicator.
    body, has_findings = build_comment(art_dir, run_url=run_url)
    # Write comment Markdown using UTF-8 encoding.
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(body)
    # Print "1" if findings exist, "0" otherwise.
    print("1" if has_findings else "0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
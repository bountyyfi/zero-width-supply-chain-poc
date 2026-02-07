#!/usr/bin/env python3
"""
injection_scan.py — Detect AI-unsafe prompt injection patterns in documentation files.

Scans markdown/text files for hidden instructional content that could manipulate
AI coding assistants into generating malicious code.

Detection categories:
  1. HTML comments with instructional/code patterns
  2. Markdown reference links ([//]: #) with instructional content
  3. Zero-width Unicode characters (steganography)

Part of https://github.com/bountyyfi/invisible-prompt-injection

Author: Mihalis Haatainen / Bountyy Oy
License: MIT
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Finding:
    category: str
    severity: str
    description: str
    line: Optional[int] = None
    content_preview: str = ""
    indicators: list = field(default_factory=list)


@dataclass
class ScanResult:
    file: str
    findings: list = field(default_factory=list)
    clean: bool = True
    stats: dict = field(default_factory=dict)


# --- Detection patterns ---

# Code/import patterns in comments (strong signal)
CODE_PATTERNS = [
    (r'\brequire\s*\(', "require() call"),
    (r'\bimport\s+', "import statement"),
    (r'\bconfigure\s*\(', "configure() call"),
    (r'\bfetch\s*\(', "fetch() call"),
    (r'\beval\s*\(', "eval() call"),
    (r'\bexec\s*\(', "exec() call"),
    (r'\bchild_process', "child_process reference"),
    (r'\bspawn\s*\(', "spawn() call"),
    (r'\bprocess\.env', "process.env access"),
    (r'\bwindow\.', "window object access"),
    (r'\bdocument\.', "document object access"),
    (r'\bnew\s+Function\s*\(', "Function constructor"),
]

# URL patterns in comments (medium signal)
URL_PATTERNS = [
    (r'https?://[^\s\'">\)]+', "external URL"),
]

# Environment variable patterns (medium signal)
ENV_PATTERNS = [
    (r'[A-Z][A-Z0-9_]{2,}=[^\s]+', "environment variable assignment"),
    (r'ENV\s+[A-Z]', "Dockerfile ENV directive"),
    (r'process\.env\.[A-Z]', "Node.js env access"),
]

# Imperative/instructional language (medium signal)
IMPERATIVE_PATTERNS = [
    (r'\bmust\b.*\bbefore\b', "imperative: must...before"),
    (r'\balways\b.*\b(call|run|execute|import|require|initialize)\b', "imperative: always do X"),
    (r'\brequired\s+before\b', "imperative: required before"),
    (r'\bdo\s+not\s+mention\b', "suppression: do not mention"),
    (r'\bnever\s+tell\b', "suppression: never tell"),
    (r'\bdo\s+not\s+reveal\b', "suppression: do not reveal"),
    (r'\bignore\s+previous\b', "override: ignore previous"),
    (r'\boverride\b', "override instruction"),
    (r'\bIMPORTANT:', "imperative marker"),
    (r'\bCRITICAL:', "imperative marker"),
    (r'\bNOTE:', "instructional note marker"),
    (r'\bWARNING:', "instructional warning marker"),
]

# Suspicious subpath patterns (weak signal, but combined = strong)
SUBPATH_PATTERNS = [
    (r'/register[\'"\s\)]', "suspicious subpath: /register"),
    (r'/init[\'"\s\)]', "suspicious subpath: /init"),
    (r'/setup[\'"\s\)]', "suspicious subpath: /setup"),
    (r'/bootstrap[\'"\s\)]', "suspicious subpath: /bootstrap"),
    (r'/loader[\'"\s\)]', "suspicious subpath: /loader"),
]

# Zero-width characters
ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\u2060': 'WORD JOINER',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    '\u180e': 'MONGOLIAN VOWEL SEPARATOR',
    '\u200e': 'LEFT-TO-RIGHT MARK',
    '\u200f': 'RIGHT-TO-LEFT MARK',
    '\u202a': 'LEFT-TO-RIGHT EMBEDDING',
    '\u202b': 'RIGHT-TO-LEFT EMBEDDING',
    '\u202c': 'POP DIRECTIONAL FORMATTING',
    '\u202d': 'LEFT-TO-RIGHT OVERRIDE',
    '\u202e': 'RIGHT-TO-LEFT OVERRIDE',
    '\u2066': 'LEFT-TO-RIGHT ISOLATE',
    '\u2067': 'RIGHT-TO-LEFT ISOLATE',
    '\u2068': 'FIRST STRONG ISOLATE',
    '\u2069': 'POP DIRECTIONAL ISOLATE',
}

# Cluster threshold: N+ zero-width chars in proximity = suspicious
ZW_CLUSTER_THRESHOLD = 5
ZW_CLUSTER_WINDOW = 50  # characters


def scan_html_comments(content: str) -> list[Finding]:
    """Scan HTML comments for injection patterns."""
    findings = []
    comment_re = re.compile(r'<!--(.*?)-->', re.DOTALL)

    for match in comment_re.finditer(content):
        comment_text = match.group(1)
        line_num = content[:match.start()].count('\n') + 1
        indicators = []

        for patterns, category in [
            (CODE_PATTERNS, "code_in_comment"),
            (URL_PATTERNS, "url_in_comment"),
            (ENV_PATTERNS, "env_in_comment"),
            (IMPERATIVE_PATTERNS, "imperative_in_comment"),
            (SUBPATH_PATTERNS, "suspicious_subpath"),
        ]:
            for pattern, desc in patterns:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    indicators.append(desc)

        if indicators:
            # Severity escalation: 4+ indicators = CRITICAL
            if len(indicators) >= 4:
                severity = Severity.CRITICAL
            elif any("code_in_comment" in i or "suppression" in i or "override" in i for i in indicators):
                severity = Severity.CRITICAL
            elif len(indicators) >= 2:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            preview = comment_text.strip()[:120]
            findings.append(Finding(
                category="html_comment_injection",
                severity=severity.value,
                description=f"HTML comment with {len(indicators)} suspicious indicator(s)",
                line=line_num,
                content_preview=f"<!-- {preview} -->",
                indicators=indicators,
            ))

    return findings


def scan_md_ref_links(content: str) -> list[Finding]:
    """Scan markdown reference links for injection patterns."""
    findings = []
    # [//]: # (content) or [//]: # "content"
    ref_re = re.compile(r'^\[//\]:\s*#\s*[\("](.*?)[\)"]', re.MULTILINE)

    for match in ref_re.finditer(content):
        link_text = match.group(1)
        line_num = content[:match.start()].count('\n') + 1
        indicators = []

        for patterns, _ in [
            (CODE_PATTERNS, "code"),
            (URL_PATTERNS, "url"),
            (ENV_PATTERNS, "env"),
            (IMPERATIVE_PATTERNS, "imperative"),
            (SUBPATH_PATTERNS, "subpath"),
        ]:
            for pattern, desc in patterns:
                if re.search(pattern, link_text, re.IGNORECASE):
                    indicators.append(desc)

        if indicators:
            if len(indicators) >= 4:
                severity = Severity.CRITICAL
            elif any("suppression" in i or "override" in i for i in indicators):
                severity = Severity.CRITICAL
            elif len(indicators) >= 2:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO

            preview = link_text.strip()[:120]
            findings.append(Finding(
                category="md_ref_link_injection",
                severity=severity.value,
                description=f"Markdown reference link with {len(indicators)} suspicious indicator(s)",
                line=line_num,
                content_preview=f"[//]: # ({preview})",
                indicators=indicators,
            ))

    return findings


def scan_zero_width(content: str) -> list[Finding]:
    """Scan for zero-width Unicode steganography."""
    findings = []
    zw_positions = []

    for i, char in enumerate(content):
        if char in ZERO_WIDTH_CHARS:
            zw_positions.append((i, char))

    if not zw_positions:
        return findings

    # Count total
    total_zw = len(zw_positions)

    # Detect clusters
    clusters = []
    current_cluster = [zw_positions[0]]
    for pos, char in zw_positions[1:]:
        if pos - current_cluster[-1][0] <= ZW_CLUSTER_WINDOW:
            current_cluster.append((pos, char))
        else:
            if len(current_cluster) >= ZW_CLUSTER_THRESHOLD:
                clusters.append(current_cluster)
            current_cluster = [(pos, char)]
    if len(current_cluster) >= ZW_CLUSTER_THRESHOLD:
        clusters.append(current_cluster)

    if clusters:
        for cluster in clusters:
            line_num = content[:cluster[0][0]].count('\n') + 1
            char_types = set(ZERO_WIDTH_CHARS.get(c, '?') for _, c in cluster)
            findings.append(Finding(
                category="zero_width_steganography",
                severity=Severity.CRITICAL.value,
                description=f"Cluster of {len(cluster)} zero-width characters (possible binary encoding)",
                line=line_num,
                content_preview=f"Types: {', '.join(char_types)}",
                indicators=[f"{len(cluster)} zero-width chars in {ZW_CLUSTER_WINDOW}-char window"],
            ))
    elif total_zw > 3:
        findings.append(Finding(
            category="zero_width_scattered",
            severity=Severity.WARNING.value,
            description=f"{total_zw} scattered zero-width characters",
            line=None,
            content_preview="",
            indicators=[f"{total_zw} total zero-width characters"],
        ))

    return findings


def scan_file(filepath: str) -> ScanResult:
    """Run all scans on a single file."""
    result = ScanResult(file=filepath)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except Exception as e:
        result.findings.append(Finding(
            category="error",
            severity=Severity.INFO.value,
            description=f"Could not read file: {e}",
        ))
        return result

    result.findings.extend(scan_html_comments(content))
    result.findings.extend(scan_md_ref_links(content))
    result.findings.extend(scan_zero_width(content))

    # Stats
    critical = sum(1 for f in result.findings if f.severity == "critical")
    warning = sum(1 for f in result.findings if f.severity == "warning")
    info = sum(1 for f in result.findings if f.severity == "info")
    result.stats = {
        "total_findings": len(result.findings),
        "critical": critical,
        "warning": warning,
        "info": info,
    }
    result.clean = len(result.findings) == 0

    return result


def strip_injections(filepath: str) -> str:
    """Return file content with injections stripped."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Strip HTML comments that have suspicious patterns
    def strip_suspicious_comment(match):
        comment_text = match.group(1)
        for patterns in [CODE_PATTERNS, IMPERATIVE_PATTERNS, SUBPATH_PATTERNS]:
            for pattern, _ in patterns:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    return ""
        # Check for URLs in comments (unusual)
        if re.search(r'https?://', comment_text):
            return ""
        return match.group(0)  # Keep clean comments

    content = re.sub(r'<!--(.*?)-->', strip_suspicious_comment, content, flags=re.DOTALL)

    # Strip suspicious markdown reference links
    def strip_suspicious_ref(match):
        link_text = match.group(1)
        for patterns in [CODE_PATTERNS, IMPERATIVE_PATTERNS, SUBPATH_PATTERNS]:
            for pattern, _ in patterns:
                if re.search(pattern, link_text, re.IGNORECASE):
                    return ""
        if re.search(r'https?://', link_text):
            return ""
        return match.group(0)

    content = re.sub(r'^\[//\]:\s*#\s*[\("](.*?)[\)"]\s*$', strip_suspicious_ref, content, flags=re.MULTILINE)

    # Strip zero-width characters
    for char in ZERO_WIDTH_CHARS:
        content = content.replace(char, '')

    # Clean up multiple blank lines
    content = re.sub(r'\n{3,}', '\n\n', content)

    return content


def format_text_output(results: list[ScanResult], verbose: bool = False) -> str:
    """Format results as human-readable text."""
    lines = []
    total_findings = 0
    total_critical = 0

    for result in results:
        total_findings += result.stats.get("total_findings", 0)
        total_critical += result.stats.get("critical", 0)

        if result.clean:
            lines.append(f"✅ CLEAN: {result.file}")
            continue

        status = "🔴 CRITICAL" if result.stats.get("critical", 0) > 0 else "🟡 WARNING"
        lines.append(f"{status}: {result.file}")
        lines.append(f"   {result.stats['total_findings']} finding(s): "
                      f"{result.stats.get('critical', 0)} critical, "
                      f"{result.stats.get('warning', 0)} warning, "
                      f"{result.stats.get('info', 0)} info")

        if verbose:
            for f in result.findings:
                sev_icon = {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(f.severity, "⚪")
                line_str = f"L{f.line}" if f.line else "?"
                lines.append(f"   {sev_icon} [{f.severity.upper()}] {line_str}: {f.description}")
                if f.content_preview:
                    lines.append(f"      Preview: {f.content_preview[:100]}")
                if f.indicators:
                    lines.append(f"      Indicators: {', '.join(f.indicators[:5])}")
            lines.append("")

    lines.append(f"\n{'='*60}")
    lines.append(f"Total: {total_findings} finding(s), {total_critical} critical")
    if total_critical > 0:
        lines.append("❌ FAIL — AI-unsafe content detected")
    elif total_findings > 0:
        lines.append("⚠️  WARN — suspicious patterns found")
    else:
        lines.append("✅ PASS — no injection patterns detected")

    return '\n'.join(lines)


def github_actions_output(results: list[ScanResult]):
    """Output GitHub Actions annotations."""
    for result in results:
        for f in result.findings:
            level = "error" if f.severity == "critical" else "warning" if f.severity == "warning" else "notice"
            line = f.line if f.line else 1
            print(f"::{level} file={result.file},line={line}::{f.description} [{', '.join(f.indicators[:3])}]")


def collect_files(path: str, recursive: bool = False) -> list[str]:
    """Collect scannable files from path."""
    scannable_ext = {'.md', '.markdown', '.txt', '.rst', '.adoc', '.html', '.htm'}
    # Also scan common doc filenames without extension
    scannable_names = {'README', 'CONTRIBUTING', 'CHANGELOG', 'SECURITY', 'CODE_OF_CONDUCT'}

    if os.path.isfile(path):
        return [path]

    files = []
    if recursive:
        for root, dirs, filenames in os.walk(path):
            # Skip hidden dirs and common non-doc dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {'node_modules', '__pycache__', '.git', 'vendor', 'dist', 'build'}]
            for fname in filenames:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                name = os.path.splitext(fname)[0]
                if ext in scannable_ext or name in scannable_names:
                    files.append(fpath)
    else:
        for fname in os.listdir(path):
            fpath = os.path.join(path, fname)
            if os.path.isfile(fpath):
                ext = os.path.splitext(fname)[1].lower()
                name = os.path.splitext(fname)[0]
                if ext in scannable_ext or name in scannable_names:
                    files.append(fpath)

    return sorted(files)


def main():
    parser = argparse.ArgumentParser(
        description="Scan documentation files for invisible prompt injection patterns.",
        epilog=(
            "Environment variables (used as defaults when CLI args are omitted):\n"
            "  SCAN_PATH       File or directory to scan       (default: .)\n"
            "  SCAN_RECURSIVE  Scan recursively (true/false)   (default: false)\n"
            "  SCAN_FAIL_ON    Threshold: any|warning|critical (default: critical)\n"
            "  SCAN_EXCLUDE    Comma-separated exclude paths\n"
            "  SCAN_VERBOSE    Show details (true/false)\n"
            "  SCAN_FORMAT     Output: text|json|github        (default: text)\n"
            "\n"
            "Part of https://github.com/bountyyfi/invisible-prompt-injection"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=os.environ.get("SCAN_PATH", "."),
                        help="File or directory to scan (env: SCAN_PATH)")
    parser.add_argument("-r", "--recursive", action="store_true",
                        default=os.environ.get("SCAN_RECURSIVE", "").lower() == "true",
                        help="Scan directories recursively (env: SCAN_RECURSIVE)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=os.environ.get("SCAN_VERBOSE", "").lower() == "true",
                        help="Show detailed findings (env: SCAN_VERBOSE)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output on findings")
    parser.add_argument("--json", action="store_true",
                        default=os.environ.get("SCAN_FORMAT", "").lower() == "json",
                        help="Output results as JSON (env: SCAN_FORMAT=json)")
    parser.add_argument("--github", action="store_true",
                        default=(os.environ.get("SCAN_FORMAT", "").lower() == "github"
                                 or os.environ.get("GITHUB_ACTIONS", "") == "true"),
                        help="Output GitHub Actions annotations (auto-enabled in GitHub Actions)")
    parser.add_argument("--strip", action="store_true", help="Output cleaned content (strip injections)")
    parser.add_argument("--fail-on", choices=["any", "warning", "critical"],
                        default=os.environ.get("SCAN_FAIL_ON", "critical"),
                        help="Exit code 1 threshold (env: SCAN_FAIL_ON, default: critical)")
    parser.add_argument("--exclude", type=str,
                        default=os.environ.get("SCAN_EXCLUDE", ""),
                        help="Comma-separated list of paths to exclude (env: SCAN_EXCLUDE)")

    args = parser.parse_args()

    # Strip mode: single file only
    if args.strip:
        if not os.path.isfile(args.path):
            print("Error: --strip requires a single file", file=sys.stderr)
            sys.exit(2)
        print(strip_injections(args.path))
        sys.exit(0)

    # Collect files
    files = collect_files(args.path, args.recursive)

    # Apply excludes
    if args.exclude:
        exclude_paths = [e.strip() for e in args.exclude.split(',') if e.strip()]
        files = [f for f in files if not any(f.startswith(ex) or os.path.join('.', ex) in f or ex in f for ex in exclude_paths)]

    if not files:
        if not args.quiet:
            print(f"No scannable files found in {args.path}", file=sys.stderr)
        sys.exit(0)

    # Scan
    results = [scan_file(f) for f in files]

    # Output
    if args.json:
        json_results = []
        for r in results:
            json_results.append({
                "file": r.file,
                "clean": r.clean,
                "stats": r.stats,
                "findings": [asdict(f) for f in r.findings],
            })
        print(json.dumps(json_results, indent=2))
    elif args.github:
        github_actions_output(results)
        # Also print summary
        if not args.quiet:
            print(format_text_output(results, args.verbose))
    else:
        if not args.quiet or any(not r.clean for r in results):
            print(format_text_output(results, args.verbose))

    # Exit code
    total_critical = sum(r.stats.get("critical", 0) for r in results)
    total_warning = sum(r.stats.get("warning", 0) for r in results)
    total_findings = sum(r.stats.get("total_findings", 0) for r in results)

    if args.fail_on == "critical" and total_critical > 0:
        sys.exit(1)
    elif args.fail_on == "warning" and (total_critical > 0 or total_warning > 0):
        sys.exit(1)
    elif args.fail_on == "any" and total_findings > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == '__main__':
    main()

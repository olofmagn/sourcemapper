import argparse
import json
import re
import sys
import requests
import yaml

from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

"""
Reconstruct original source files from a JavaScript sourcemap and
scan it for leaked secrets and internal endpoints
"""

# Disable warnings
requests.packages.urllib3.disable_warnings()

# Color codes
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
NC = "\033[0m"

# Constants
WIDTH = 44

# Default path to the scan-rule file
DEFAULT_PATTERNS = str(Path(__file__).resolve().parent / "scan_patterns.yaml")

# Strip URI-style scheme prefixes
SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9.+-]*://+")

# Strip leading relative/absolute path prefixes
LEADING_PREFIX = re.compile(r"^(?:\.\.?/|/)+")

# Browser-like User-Agent for HTTP requests
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/139.0.0.0 Safari/537.36"
)

BANNER = rf"""
  ___  ___  _   _ _ __ ___ ___ _ __ ___   __ _ _ __  _ __   ___ _ __
 / __|/ _ \| | | | '__/ __/ _ \ '_ ` _ \ / _` | '_ \| '_ \ / _ \ '__|
 \__ \ (_) | |_| | | | (_|  __/ | | | | | (_| | |_) | |_) |  __/ |
 |___/\___/ \__,_|_|  \___\___|_| |_| |_|\__,_| .__/| .__/ \___|_|
                                              |_|   |_|
                    Source map extractor v1.0
                         by olofmagn
"""


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments

    Returns:
    - argparse.Namespace: Parsed command-line arguments
    """

    parser = argparse.ArgumentParser(
        description="Reconstruct original sources from a .js.map and scan them for endpoints/secrets"
    )

    parser.add_argument(
        "source",
        help="URL or local path to a .js.map sourcemap file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="sourcemap_out",
        help="Output directory for the reconstructed source tree",
    )

    parser.add_argument(
        "-p",
        "--patterns",
        default=DEFAULT_PATTERNS,
        help="Path to the YAML scan-rule file",
    )

    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip the endpoint/secret scan",
    )

    parser.add_argument(
        "--report",
        default="report.txt",
        help="Report file written after a scan",
    )

    return parser.parse_args()


def pluralize(count: int, word: str) -> str:
    """
    Pluralize words based on count

    Args:
    - count (int): The number of items
    - word (str): The word to pluralize

    Returns:
    - str: The pluralized word with count
    """

    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def create_session() -> requests.Session:
    """
    Create a configured session object

    Returns:
    - requests.Session: A configured session object for making HTTP requests
    """

    session = requests.Session()
    session.verify = False

    # Set default headers
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )

    return session


def fetch_map(session: requests.Session, url: str) -> Optional[Dict]:
    """
    Fetch and parse a sourcemap from a URL

    Args:
    - session (requests.Session): configured session for HTTP fetches
    - url (str): URL to the .js.map file

    Returns:
    - Optional[Dict]: parsed sourcemap object
    """

    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"{RED}[!] Failed to fetch sourcemap: {e}{NC}")
        return None


def read_map_file(source: str) -> Optional[Dict]:
    """
    Read and parse a sourcemap from a local file path

    Args:
    - source (str): local path to the .js.map file

    Returns:
    - Optional[Dict]: parsed sourcemap object
    """

    try:
        with open(source, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"{RED}[!] Failed to read sourcemap: {e}{NC}")
        return None


def load_map(session: requests.Session, source: str) -> Optional[Dict]:
    """
    Load a sourcemap from a URL or a local file path

    Args:
    - session (requests.Session): configured session for HTTP fetches
    - source (str): URL or local path to the .js.map file

    Returns:
    - Optional[Dict]: parsed sourcemap object
    """

    if source.startswith(("http://", "https://")):
        return fetch_map(session, source)

    return read_map_file(source)


def iter_source_contents(sourcemap: Dict) -> Iterator[Tuple[str, Optional[str]]]:
    """
    Iterate over sources paired with their sourcesContent entries

    Args:
    - sourcemap (Dict): parsed sourcemap object

    Yields:
    - Tuple[str, Optional[str]]: source path and embedded source content
    """

    sources = sourcemap.get("sources", [])
    contents = sourcemap.get("sourcesContent", [])

    for index, path in enumerate(sources):
        # A map may list more sources than it embeds content
        if index >= len(contents):
            continue

        yield path, contents[index]


def safe_dest(outdir: Path, raw_path: str) -> Optional[Path]:
    """
    Resolve a sourcemap source path to a destination inside outdir

    Args:
    - outdir (Path): output directory root
    - raw_path (str): raw source path from the sourcemap

    Returns:
    - Optional[Path]: safe destination path inside outdir, or None
    """

    # Normalize into a clean path
    clean = raw_path.replace("\\", "/").replace("\x00", "")
    clean = SCHEME_PREFIX.sub("", clean)
    clean = LEADING_PREFIX.sub("", clean)

    if not clean:
        return None

    root = outdir.resolve()

    # Resolve '..' segments
    safe_parts = []
    for part in Path(clean).parts:
        if part in ("", "."):
            continue

        if part == "..":
            if safe_parts:
                safe_parts.pop()
            continue

        safe_parts.append(part)

    if not safe_parts:
        return None

    dest = (root / Path(*safe_parts)).resolve()

    if root not in dest.parents and dest != root:
        return None

    return dest


def write_source(dest: Path, content: str) -> bool:
    """
    Write one source content to dest

    Args:
    - dest (Path): destination path
    - content (str): file content to write

    Returns:
    - bool: True if written
    """

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return True
    except OSError as e:
        print(f"{YELLOW}[!] Could not write '{dest}': {e}{NC}")
        return False


def extract_sources(sourcemap: Dict, outdir: str) -> int:
    """
    Write every embedded source file from the map to disk under outdir

    Args:
    - sourcemap (Dict): parsed sourcemap object
    - outdir (str): output directory for the reconstructed tree

    Returns:
    - int: number of files written
    """

    if not sourcemap.get("sourcesContent"):
        print(
            f"{RED}[!] No sourcesContent array - map only has VLQ mappings, "
            f"original source is not embedded{NC}"
        )
        return 0

    sources = sourcemap.get("sources", [])
    print(f"{GREEN}[+] 📄 {pluralize(len(sources), 'source')} in map{NC}")

    root = Path(outdir).resolve()
    written = 0

    for path, content in iter_source_contents(sourcemap):
        if content is None:
            continue

        dest = safe_dest(root, path)
        if dest is not None and write_source(dest, content):
            written += 1

    print(f"{GREEN}[+] ✅ Extracted {pluralize(written, 'file')} to: {root}{NC}")

    return written


def collect_files(sourcemap: Dict) -> List[Tuple[str, List[Tuple[int, str, str]]]]:
    """
    Pair each non-empty source with its scannable lines

    Args:
    - sourcemap (Dict): parsed sourcemap object

    Returns:
    - List[Tuple[str, List[Tuple[int, str, str]]]]: (source path,
      [(1-based line no, raw line, stripped line), ...]) pairs
    """

    files = []

    for path, content in iter_source_contents(sourcemap):
        # Skip empty sources and third-party modules
        if not content or "node_modules" in path:
            continue

        rows = []
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if not stripped:
                continue

            rows.append((line_no, line, stripped))

        files.append((path, rows))

    return files


def read_pattern_file(path: str) -> Dict:
    """
    Read and parse the YAML scan-rule file

    Args:
    - path (str): path to the YAML scan-rule file

    Returns:
    - Dict: parsed YAML mapping (exits on read/parse error)
    """

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        print(f"{RED}[!] Failed to load pattern file '{path}': {e}{NC}")
        sys.exit(1)


def validate_rule(index: int, raw: Dict) -> Optional[Tuple[str, str]]:
    """
    Check a raw rule's required fields

    Args:
    - index (int): 1-based position of the rule in the file
    - raw (Dict): unparsed rule mapping from the YAML file

    Returns:
    - Optional[Tuple[str, str]]: (label, pattern)
    """

    label = raw.get("label")
    pattern = raw.get("pattern")

    if not label or not pattern:
        print(f"{YELLOW}[!] Rule #{index} missing label/pattern - skipped{NC}")
        return None

    return label, pattern


def compile_rule(index: int, raw: Dict) -> Optional[Dict]:
    """
    Validate and compile a single raw scan rule

    Args:
    - index (int): 1-based position of the rule in the file
    - raw (Dict): unparsed rule mapping from the YAML file

    Returns:
    - Optional[Dict]: compiled rule
    """

    valid = validate_rule(index, raw)

    if valid is None:
        return None

    label, pattern = valid

    flags = re.IGNORECASE if raw.get("ignorecase") else 0

    try:
        compiled = re.compile(pattern, flags)
        return {
            "label": label,
            "pattern": compiled,
        }
    except re.error as e:
        print(f"{YELLOW}[!] Rule '{label}' regex error ({e}) - skipped{NC}")
        return None


def load_patterns(path: str) -> List[Dict]:
    """
    Load and compile scan rules from a YAML file

    Args:
    - path (str): path to the YAML scan-rule file

    Returns:
    - List[Dict]: compiled rules with keys
    """

    data = read_pattern_file(path)

    rules = []

    # Enumerate rules from file
    for i, raw in enumerate(data.get("rules", []), 1):
        rule = compile_rule(i, raw)
        if rule is not None:
            rules.append(rule)

    return rules


def scan_rule(
    rule: Dict, files: List[Tuple[str, List[Tuple[int, str, str]]]]
) -> List[str]:
    """
    Run a single compiled rule over every file's prepared lines

    Args:
    - rule (Dict): one compiled scan rule
    - files (List[Tuple[str, List[Tuple[int, str, str]]]]): prepared
      (path, [(line no, raw line, stripped line), ...]) pairs

    Returns:
    - List[str]: matched entries
    """

    results = []
    pattern = rule["pattern"]

    for path, rows in files:
        for line_no, line, stripped in rows:
            if pattern.search(line):
                results.append(f"{path}:{line_no}  {stripped[:120]}")

    return results


def ansi_colors(enabled: bool) -> Tuple[str, str, str, str]:
    """
    Return ANSI color codes when enabled, otherwise empty strings.

    Args:
    - enabled (bool): whether ANSI colors should be included

    Returns:
    - Tuple[str, str, str, str]: green, yellow, magenta, reset
    """

    if enabled:
        return GREEN, YELLOW, MAGENTA, NC

    return "", "", "", ""


def format_findings(findings: List[Tuple[str, List[str]]], color: bool) -> str:
    """
    Render grouped findings as text, optionally with ANSI colors

    Args:
    - findings (List[Tuple[str, List[str]]]): (rule label, matched lines) pairs
    - color (bool): include ANSI color codes (for the terminal, not files)

    Returns:
    - str: rendered findings (detail block; the total lives in format_summary)
    """

    green, _, magenta, nc = ansi_colors(color)

    if not findings:
        return f"{green}[+] Nothing matched{nc}"

    output = []

    for index, (label, results) in enumerate(findings):
        if index > 0:
            output.append("")

        output.append(f"{green}[{label}] {len(results)}{nc}")

        for result in results:
            output.append(f"  {result}")

    output.append(f"{magenta}{'-' * WIDTH}{nc}")

    return "\n".join(output)

def format_summary(findings: List[Tuple[str, List[str]]], color: bool) -> str:
    """
    Render a per-category count recap, sorted by count (largest first)

    Args:
    - findings (List[Tuple[str, List[str]]]): (rule label, matched lines) pairs
    - color (bool): include ANSI color codes (for the terminal, not files)

    Returns:
    - str: rendered summary block, ending with the grand total
    """

    green, yellow, magenta, nc = ansi_colors(color)

    counts = sorted(
        ((label, len(results)) for label, results in findings),
        key=lambda item: item[1],
        reverse=True,
    )
    total = sum(count for _, count in counts)

    output = [f"{magenta}Summary{nc}"]

    for label, count in counts:
        dots = "." * max(3, WIDTH - len(label) - len(str(count)))
        output.append(f"  {green}{label}{nc} {dots} {count}")

    output.append(f"{magenta}{'-' * WIDTH}{nc}")
    output.append(f"{yellow}[~] {pluralize(total, 'finding')} across categories{nc}")

    return "\n".join(output)


def print_summary(findings: List[Tuple[str, List[str]]]) -> None:
    """
    Pretty-print scan findings grouped by rule label

    Args:
    - findings (List[Tuple[str, List[str]]]): (rule label, matched lines) pairs
    """

    print(format_findings(findings, color=True))

    if findings:
        print(format_summary(findings, color=True))


def write_output(output_path: str, findings: List[Tuple[str, List[str]]]) -> bool:
    """
    Write scan findings to a plain-text output file

    Args:
    - output_path (str): path to the output file
    - findings (List[Tuple[str, List[str]]]): grouped scan findings

    Returns:
    - bool: True if the report was written
    """

    try:
        report = format_findings(findings, color=False)
        if findings:
            report += "\n\n" + format_summary(findings, color=False)
        Path(output_path).write_text(report + "\n", encoding="utf-8")
        return True
    except OSError as e:
        print(
            f"{YELLOW}[!] Could not write report "
            f"'{output_path}': {e}{NC}"
        )
        return False


def scan_sources(
    files: List[Tuple[str, List[Tuple[int, str, str]]]],
    rules: List[Dict],
) -> List[Tuple[str, List[str]]]:
    """
    Run the compiled YAML rules over the prepared source lines

    Args:
    - files (List[Tuple[str, List[Tuple[int, str, str]]]]): prepared source rows
    - rules (List[Dict]): compiled scan rules

    Returns:
    - List[Tuple[str, List[str]]]: (rule label, matched lines) pairs
    """

    if not rules:
        print(f"{YELLOW}[!] No scan rules loaded - skipping scan{NC}")
        return []

    print(f"{MAGENTA}{'-' * WIDTH}{NC}")
    print(
        f"{BLUE}[~] 🔍 Scanning {pluralize(len(files), 'recovered source')} "
        f"with {pluralize(len(rules), 'rule')}{NC}\n"
    )

    findings = []

    for rule in rules:
        results = scan_rule(rule, files)
        if results:
            findings.append((rule["label"], results))

    print_summary(findings)

    return findings


def run(
    source: str,
    outdir: str,
    patterns_path: str,
    scan: bool,
    report_path: str,
) -> None:
    """
    Run the extraction and optional scan

    Args:
    - source (str): URL or local path to the .js.map file
    - outdir (str): output directory for the reconstructed tree
    - patterns_path (str): path to the YAML scan-rule file
    - scan (bool): endpoint/secret scan after extraction
    - report_path (str): path to write the plain-text report
    """

    print(f"{BLUE}[~] 📂 Extracting {source}{NC}")
    print(f"{MAGENTA}{'-' * WIDTH}{NC}")

    session = create_session()

    sourcemap = load_map(session, source)
    if sourcemap is None:
        sys.exit(1)

    extract_sources(sourcemap, outdir)

    findings = []

    if scan:
        files = collect_files(sourcemap)
        if files:
            rules = load_patterns(patterns_path)
            findings = scan_sources(files, rules)

    if scan and write_output(report_path, findings):
        print(f"{GREEN}[+] Report written to: {Path(report_path).resolve()}{NC}")


def main():
    print(f"{RED}{BANNER}{NC}")

    args = parse_args()

    run(
        args.source,
        args.output,
        args.patterns,
        not args.no_scan,
        args.report,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[!] Unexpected Error: {e}{NC}")
        sys.exit(1)

#!/usr/bin/env python3
"""
verify_rules_flexible.py - Flexible version that takes log folder and combined JSON as input
Supports both new naming format (fail_to_pass/pass_to_pass) and legacy format (p2p/f2p).
Implements dynamic log file discovery for patterns like *_base.log, *_before.log, *_after.log.
"""
import argparse
from pathlib import Path
import json, re, ast, sys, glob
from typing import Dict, Set, List, Iterable, Optional, Tuple
from collections import defaultdict

# Matches test patterns anywhere in the line (using word boundary):
#   test yank::explicit_version ... ok
#   test workspaces::virtual_primary_package_env_var ... ok  
#   test bad_config::bad_test_name ... FAILED
#   test src/... (doc-tests) ... ignored
#   prefix text...test map::test_unicase_ascii ... ok (handles concatenated/embedded output)
_TEST_LINE_RE = re.compile(
    r'\btest\s+(.+?)\s+\.\.\.\s+(ok|FAILED|ignored)',
    re.IGNORECASE,
)

# Enhanced patterns for improved duplicate detection
_FILE_BOUNDARY_PATTERNS = [
    re.compile(r'Running\s+([^/\s]+(?:/[^/\s]+)*\.rs)\s*\('),
    re.compile(r'===\s*Running\s+(.+\.rs)'),
    re.compile(r'test\s+result:\s+ok\.\s+\d+\s+passed.*for\s+(.+\.rs)'),
]

_ENHANCED_TEST_PATTERNS = [
    re.compile(r'\btest\s+([^\s.]+(?:::[^\s.]+)*)\s*\.{2,}\s*(ok|FAILED|ignored)', re.IGNORECASE),
    re.compile(r'test\s+([a-zA-Z_][a-zA-Z0-9_:]*)\s+\.\.\.\s+(ok|FAILED|ignored)', re.IGNORECASE),
]

def parse_rust_tests_text(text: str) -> Dict[str, object]:
    passed, failed, ignored = set(), set(), set()
    freq = defaultdict(int)
    test_contexts = defaultdict(list)  # Track line numbers and contexts for each test name
    lines = text.splitlines()
    
    # First pass: handle normal test lines and concatenated results
    for line_num, line in enumerate(lines):
        m = _TEST_LINE_RE.search(line)  # Use search instead of match to find test anywhere in line
        if not m:
            continue
        name, status = m.groups()
        status = status.lower()
        freq[name] += 1
        test_contexts[name].append({
            'line_num': line_num,
            'full_line': line.strip(),
            'status': status
        })
        if status == "ok":
            passed.add(name)
        elif status == "failed":
            failed.add(name)
        elif status == "ignored":
            ignored.add(name)
    
    # Second pass: handle cases where test result is on a separate line or buried in output
    # Look for test lines that start but don't have an immediate result
    pending_tests = {}
    for i, line in enumerate(lines):
        # Match test lines that start with "test ... ... " but may not have immediate status
        test_start_match = re.search(r'\btest\s+(.+?)\s+\.\.\.\s*(.*?)$', line, re.IGNORECASE)
        if test_start_match:
            name, remainder = test_start_match.groups()
            # Skip if we already found this test with a clear status
            if name in passed or name in failed or name in ignored:
                continue
            # If remainder doesn't contain a clear status, this test might have result later
            if not re.search(r'\b(ok|failed|ignored)\b', remainder, re.IGNORECASE):
                pending_tests[name] = i
    
    # For pending tests, search more aggressively for their results
    for name, start_line in pending_tests.items():
        found_result = False
        # Look in subsequent lines for the result, potentially many lines later
        for j in range(start_line + 1, min(start_line + 200, len(lines))):
            line = lines[j]
            
            # Check for standalone status words
            stripped = line.strip()
            if stripped in ['ok', 'FAILED', 'ignored']:
                status = stripped.lower()
                freq[name] += 1
                if status == "ok":
                    passed.add(name)
                elif status == "failed":
                    failed.add(name)
                elif status == "ignored":
                    ignored.add(name)
                found_result = True
                break
            
            # Check for status words at the end of lines (after debug output)
            if re.search(r'\b(ok|failed|ignored)\s*$', line, re.IGNORECASE):
                status_match = re.search(r'\b(ok|failed|ignored)\s*$', line, re.IGNORECASE)
                if status_match:
                    status = status_match.group(1).lower()
                    freq[name] += 1
                    if status == "ok":
                        passed.add(name)
                    elif status == "failed":
                        failed.add(name)
                    elif status == "ignored":
                        ignored.add(name)
                    found_result = True
                    break
            
            # Stop looking if we hit another test line (but allow some leeway)
            if re.search(r'\btest\s+[\w:]+\s+\.\.\.\s*', line) and j > start_line + 5:
                break
    
    # Third pass: handle split status words like "o\nk" 
    for i, line in enumerate(lines):
        # Look for lines that end with just "o" and check if next line starts with "k"
        if line.strip() == "o" and i + 1 < len(lines) and lines[i + 1].strip() == "k":
            # Look backwards to find the corresponding test
            for j in range(i - 1, max(i - 10, -1), -1):
                test_match = re.search(r'\btest\s+([\w:]+(?:::\w+)*)\s+\.\.\.\s*o\s*$', lines[j])
                if test_match:
                    name = test_match.group(1)
                    if name not in passed and name not in failed and name not in ignored:
                        freq[name] += 1
                        passed.add(name)
                    break
        
        # Also handle the case where test line itself ends with "... o" (split across lines)
        test_with_o = re.search(r'\btest\s+([\w:]+(?:::\w+)*)\s+\.\.\.\s*o\s*$', line)
        if test_with_o and i + 1 < len(lines) and lines[i + 1].strip() == "k":
            name = test_with_o.group(1)
            if name not in passed and name not in failed and name not in ignored:
                freq[name] += 1
                passed.add(name)
    
    # Fourth pass: scan the entire text for any missed test patterns with complex formatting
    # This catches cases where output is heavily interleaved
    full_text = text
    
    # Look for patterns like "test name ... <anything> ok" across multiple lines
    # But limit the search to reasonable distances to avoid false matches
    test_starts = []
    for i, line in enumerate(lines):
        test_match = re.search(r'\btest\s+([\w:]+(?:::\w+)*)\s+\.\.\.\s*', line)
        if test_match:
            test_starts.append((i, test_match.group(1), test_match.start(), test_match.end()))
    
    # For each test start, look for the corresponding result within a reasonable range
    for line_idx, test_name, start_pos, end_pos in test_starts:
        if test_name in passed or test_name in failed or test_name in ignored:
            continue
            
        # Search forward through lines for the result
        found = False
        search_text = ""
        for j in range(line_idx, min(line_idx + 100, len(lines))):
            search_text += lines[j] + "\n"
            
            # Stop if we hit another test (but give some leeway for interleaved output)
            if j > line_idx + 5 and re.search(r'\btest\s+[\w:]+\s+\.\.\.\s*', lines[j]):
                break
        
        # Look for status in this accumulated text
        status_match = re.search(r'\b(ok|failed|ignored)\b(?![^<]*>)', search_text, re.IGNORECASE)
        if status_match:
            status = status_match.group(1).lower()
            freq[test_name] += 1
            if status == "ok":
                passed.add(test_name)
            elif status == "failed":
                failed.add(test_name)
            elif status == "ignored":
                ignored.add(test_name)

    # Also read the "failures:" block to catch names not emitted on one-line form
    collecting = False
    for line in lines:
        s = line.strip()
        if s == "failures:":
            collecting = True
            continue
        if collecting:
            if s.startswith("error:") or s.startswith("test result:"):
                collecting = False
                continue
            m = re.match(r'^\s{4}(.+?)\s*$', line)
            if m:
                name = m.group(1)
                if not name.startswith("----"):
                    failed.add(name)
                continue
            if s == "" or s.startswith("----"):
                continue
            collecting = False

    return {
        "passed": passed,
        "failed": failed,
        "ignored": ignored,
        "all": passed | failed | ignored,
        "freq": dict(freq),  # name -> occurrences in this log
    }

def discover_log_files(log_folder: Path) -> Optional[Tuple[Path, Path, Path]]:
    """
    Dynamically discover log files with patterns: *_base.log, *_before.log, *_after.log
    
    Returns:
        Tuple of (base_log_path, before_log_path, after_log_path) or None if not found
    """
    if not log_folder.exists() or not log_folder.is_dir():
        return None
    
    # Find log files with patterns
    base_files = list(log_folder.glob("*_base.log"))
    before_files = list(log_folder.glob("*_before.log"))
    after_files = list(log_folder.glob("*_after.log"))
    
    # Also check for simple names (fallback)
    if not base_files:
        base_simple = log_folder / "base.log"
        if base_simple.exists():
            base_files = [base_simple]
    
    if not before_files:
        before_simple = log_folder / "before.log"
        if before_simple.exists():
            before_files = [before_simple]
    
    if not after_files:
        after_simple = log_folder / "after.log"
        if after_simple.exists():
            after_files = [after_simple]
    
    # Check if we found all required files
    if not (base_files and before_files and after_files):
        return None
    
    # If multiple files match, try to find a consistent prefix
    if len(base_files) == 1 and len(before_files) == 1 and len(after_files) == 1:
        return base_files[0], before_files[0], after_files[0]
    
    # Try to match by prefix
    prefixes = set()
    for base_file in base_files:
        prefix = base_file.stem.replace("_base", "")
        before_match = log_folder / f"{prefix}_before.log"
        after_match = log_folder / f"{prefix}_after.log"
        
        if before_match.exists() and after_match.exists():
            return base_file, before_match, after_match
    
    # If no consistent match, take the first of each
    return base_files[0], before_files[0], after_files[0]

def parse_log_file(path: Path) -> Dict[str, object]:
    if not path.exists():
        sys.exit(f"[error] log not found: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    result = parse_rust_tests_text(text)
    result["raw_content"] = text  # Store raw content for duplicate analysis
    return result

def load_combined_json(path: Path) -> tuple[List[str], List[str]]:
    """Load combined JSON file containing both p2p and f2p lists.
    
    Supports both formats:
    - New format: {"pass_to_pass": [...], "fail_to_pass": [...]}
    - Legacy format: {"p2p": [...], "f2p": [...]}
    """
    if not path.exists():
        sys.exit(f"[error] combined JSON file not found: {path}")
    
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        
        if not isinstance(data, dict):
            sys.exit(f"[error] JSON file must contain an object")
        
        # Try new format first
        p2p = data.get("pass_to_pass")
        f2p = data.get("fail_to_pass")
        
        # Fall back to legacy format
        if p2p is None:
            p2p = data.get("p2p", [])
        if f2p is None:
            f2p = data.get("f2p", [])
        
        # Validate that we found the data
        if p2p is None or f2p is None:
            available_keys = list(data.keys())
            sys.exit(f"[error] JSON file must contain 'pass_to_pass'/'fail_to_pass' or 'p2p'/'f2p' keys. Found: {available_keys}")
        
        if not isinstance(p2p, list) or not isinstance(f2p, list):
            sys.exit(f"[error] test lists must be arrays in the JSON file")
        
        return [str(x) for x in p2p], [str(x) for x in f2p]
        
    except json.JSONDecodeError as e:
        sys.exit(f"[error] invalid JSON in {path}: {e}")

def status_lookup(names: Iterable[str], parsed: Dict[str, Set[str]]) -> Dict[str, str]:
    out = {}
    for n in names:
        if n in parsed["failed"]:
            out[n] = "failed"
        elif n in parsed["passed"]:
            out[n] = "passed"
        elif n in parsed["ignored"]:
            out[n] = "ignored"
        else:
            out[n] = "missing"
    return out

def detect_file_boundary(line: str) -> Optional[str]:
    """Detect file boundary using multiple enhanced patterns"""
    for pattern in _FILE_BOUNDARY_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None

def extract_test_info_enhanced(line: str) -> Optional[Tuple[str, str]]:
    """Extract test name and status using enhanced patterns"""
    for pattern in _ENHANCED_TEST_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1).strip(), match.group(2).strip()
    return None

def is_true_duplicate(occurrences: List[Dict]) -> bool:
    """Determine if multiple occurrences represent problematic duplicates"""
    if len(occurrences) <= 1:
        return False
    
    # Check line distance - if tests are very close together, likely duplicates
    line_numbers = [occ['line_no'] for occ in occurrences]
    line_numbers.sort()
    min_distance = min(line_numbers[i] - line_numbers[i-1] for i in range(1, len(line_numbers)))
    
    # If tests appear within 10 lines of each other, likely true duplicates
    if min_distance < 10:
        return True
    
    # Check for mixed success/failure status that might indicate retries
    statuses = [occ['status'].lower() for occ in occurrences]
    if 'failed' in statuses and 'ok' in statuses:
        return True
    
    # If all occurrences have identical context, likely problematic
    contexts = [' '.join(occ.get('context_before', []) + occ.get('context_after', [])) for occ in occurrences]
    if len(set(contexts)) == 1 and contexts[0].strip():
        return True
    
    return False

def detect_same_file_duplicates(raw_content: str) -> List[str]:
    """
    Enhanced detection of tests that appear multiple times within the same test file.
    Uses improved pattern matching and context analysis to distinguish true duplicates
    from legitimate same-named tests in different contexts.
    
    Returns list of problematic duplicate descriptions.
    """
    if not raw_content:
        return []
    
    lines = raw_content.split('\n')
    current_file = "unknown" 
    test_occurrences = defaultdict(list)  # Store detailed occurrence info
    
    for line_no, line in enumerate(lines):
        # Check for file boundary using enhanced patterns
        file_boundary = detect_file_boundary(line)
        if file_boundary:
            current_file = file_boundary
            continue
        
        # Check for test result summaries that indicate file boundaries
        if re.search(r'test result:\s*ok\.\s*\d+\s*passed', line):
            continue
            
        # Extract test information using enhanced patterns
        test_info = extract_test_info_enhanced(line)
        if test_info:
            test_name, status = test_info
            test_occurrences[current_file].append({
                'test_name': test_name,
                'status': status,
                'line_no': line_no,
                'line_content': line.strip(),
                'context_before': lines[max(0, line_no-2):line_no] if line_no >= 2 else [],
                'context_after': lines[line_no+1:min(len(lines), line_no+3)] if line_no < len(lines)-2 else []
            })
    
    # Analyze for true duplicates using context
    true_duplicates = []
    for file_name, occurrences in test_occurrences.items():
        # Group by test name
        by_test_name = defaultdict(list)
        for occurrence in occurrences:
            by_test_name[occurrence['test_name']].append(occurrence)
        
        # Check for duplicates within each test name group
        for test_name, test_occurrences_list in by_test_name.items():
            if len(test_occurrences_list) > 1:
                # Use enhanced logic to determine if it's a true duplicate
                if is_true_duplicate(test_occurrences_list):
                    line_info = [f"line {occ['line_no']}" for occ in test_occurrences_list]
                    duplicate_info = (
                        f"{test_name} (appears {len(test_occurrences_list)} times in {file_name}: "
                        f"{', '.join(line_info)})"
                    )
                    true_duplicates.append(duplicate_info)
    
    return true_duplicates

def verify_rules(base_log, before_log, after_log, p2p: List[str], f2p: List[str],
                 base_path: Path, before_path: Path, after_path: Path) -> Dict:
    universe = list(set(p2p) | set(f2p))

    base_s   = status_lookup(universe, base_log)
    before_s = status_lookup(universe, before_log)
    after_s  = status_lookup(universe, after_log)

    # 1) Failed in base present in P2P
    c1_hits = [t for t in p2p if base_s.get(t) == "failed"]
    c1 = len(c1_hits) > 0

    # 2) Failed in after present in F2P / P2P
    c2_hits = [t for t in universe if after_s.get(t) == "failed"]
    c2 = len(c2_hits) > 0

    # 3) F2P success in before
    c3_hits = [t for t in f2p if before_s.get(t) == "passed"]
    c3 = len(c3_hits) > 0

    # 4) P2P missing in base and NOT passing in before
    c4_hits = [t for t in p2p if base_s.get(t) == "missing" and before_s.get(t) == "failed"]
    c4 = len(c4_hits) > 0

    # 5) True duplicates in the same log for F2P/P2P
    # Only flag tests that appear multiple times within the same test file
    dup_map = {}
    for label, log in (("base", base_log), ("before", before_log), ("after", after_log)):
        # Detect true duplicates (same test appearing multiple times in same file)
        true_duplicates = detect_same_file_duplicates(log.get("raw_content", ""))
        
        # Only report if there are actual same-file duplicates
        if true_duplicates:
            dup_map[label] = true_duplicates[:50]
    
    # Rule C5 fails only if there are true same-file duplicates
    c5 = len(dup_map) > 0

    # P2P Rejection logic - P2P tests should pass in both base and after
    rr_considered = [t for t in p2p if not (base_s.get(t) == "passed" and after_s.get(t) == "passed")]
    rr_rejected   = [t for t in rr_considered if base_s.get(t) == "missing" and before_s.get(t) != "passed"]
    rr_ok         = [t for t in rr_considered if base_s.get(t) == "missing" and before_s.get(t) == "passed"]
    rejection_satisfied = len(rr_rejected) > 0

    # F2P Analysis
    f2p_failed_in_base = [t for t in f2p if base_s.get(t) == "failed"]
    f2p_missing_in_base = [t for t in f2p if base_s.get(t) == "missing"]
    f2p_passed_in_base = [t for t in f2p if base_s.get(t) == "passed"]
    
    f2p_passed_in_before = [t for t in f2p if before_s.get(t) == "passed"]
    f2p_failed_in_before = [t for t in f2p if before_s.get(t) == "failed"]
    f2p_missing_in_before = [t for t in f2p if before_s.get(t) == "missing"]
    
    f2p_passed_in_after = [t for t in f2p if after_s.get(t) == "passed"]
    f2p_failed_in_after = [t for t in f2p if after_s.get(t) == "failed"]
    f2p_missing_in_after = [t for t in f2p if after_s.get(t) == "missing"]

    def quick_counts(parsed, label):
        return {
            "label": label,
            "passed": len(parsed["passed"]),
            "failed": len(parsed["failed"]),
            "ignored": len(parsed["ignored"]),
            "all": len(parsed["all"]),
        }

    return {
        "inputs": {
            "base_log":   str(base_path.resolve()),
            "before_log": str(before_path.resolve()),
            "after_log":  str(after_path.resolve()),
        },
        "counts": {"P2P": len(p2p), "F2P": len(f2p)},
        "rule_checks": {
            "c1_failed_in_base_present_in_P2P": {
                "problem_detected": c1, "problamatic_tests": c1_hits
            },
            "c2_failed_in_after_present_in_F2P_or_P2P": {
                "problem_detected": c2, "problamatic_tests": c2_hits
            },
            "c3_F2P_success_in_before": {
                "problem_detected": c3, "problematic_tests": c3_hits
            },
            "c4_P2P_missing_in_base_and_not_passing_in_before": {
                "problem_detected": c4, "problematic_tests": c4_hits
            },
            "c5_duplicates_in_same_log_for_F2P_or_P2P": {
                "problem_detected": c5, "duplicate_tests_per_log": dup_map
            },
        },
        "rejection_reason": {
            "satisfied": rejection_satisfied,
            "p2p_ignored_because_passed_in_base_and_after": [t for t in p2p if base_s.get(t) == "passed" and after_s.get(t) == "passed"][:20],
            "p2p_considered": rr_considered[:50],
            "p2p_rejected": rr_rejected,
            "p2p_considered_but_ok": rr_ok,
            "f2p_ignored_because_passed_in_after": [t for t in f2p if after_s.get(t) == "passed"][:20],
            "f2p_considered": [t for t in f2p if after_s.get(t) != "passed"][:50],
            "f2p_rejected": [t for t in f2p if after_s.get(t) == "failed"][:50],
            "f2p_considered_but_ok": [t for t in f2p if after_s.get(t) == "missing"][:50],
        },
        "p2p_analysis": {
            test_name: {
                "base": base_s.get(test_name, "missing"),
                "before": before_s.get(test_name, "missing"),
                "after": after_s.get(test_name, "missing")
            } for test_name in p2p
        },
        "f2p_analysis": {
            test_name: {
                "base": base_s.get(test_name, "missing"),
                "before": before_s.get(test_name, "missing"),
                "after": after_s.get(test_name, "missing")
            } for test_name in f2p
        },
        "debug_log_counts": [
            quick_counts(base_log, "base"),
            quick_counts(before_log, "before"),
            quick_counts(after_log, "after"),
        ],
    }

def main():
    parser = argparse.ArgumentParser(
        description="Verify test rules against log files with dynamic discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover logs in current directory
  python3 main.py combined.json

  # Use logs from specific folder with auto-discovery
  python3 main.py --log-folder /path/to/logs combined.json

  # Manually specify log files
  python3 main.py --base-log project_base.log --before-log project_before.log --after-log project_after.log combined.json

  # Specify output file
  python3 main.py --output results.json combined.json

Expected JSON format (supports both formats):
{
  "pass_to_pass": ["test1", "test2", ...],    // New format
  "fail_to_pass": ["test3", "test4", ...]
}
OR
{
  "p2p": ["test1", "test2", ...],             // Legacy format
  "f2p": ["test3", "test4", ...]
}
        """)
    
    parser.add_argument("json_file", 
                       help="JSON file containing test lists")
    parser.add_argument("--log-folder", "-l", 
                       type=Path, default=Path("."),
                       help="Folder to search for log files (default: current directory)")
    parser.add_argument("--auto-discover", "-a",
                       action="store_true", default=True,
                       help="Auto-discover log files with patterns *_base.log, *_before.log, *_after.log")
    parser.add_argument("--base-log", 
                       type=Path,
                       help="Explicit path to base log file (overrides auto-discovery)")
    parser.add_argument("--before-log", 
                       type=Path,
                       help="Explicit path to before log file (overrides auto-discovery)")
    parser.add_argument("--after-log", 
                       type=Path,
                       help="Explicit path to after log file (overrides auto-discovery)")
    parser.add_argument("--output", "-o", 
                       type=Path, default=Path("verify_results.json"),
                       help="Output JSON file (default: verify_results.json)")
    parser.add_argument("--pretty", "-p", 
                       action="store_true", default=True,
                       help="Pretty-print JSON output (default: true)")
    parser.add_argument("--compact", "-c", 
                       action="store_true",
                       help="Compact JSON output (overrides --pretty)")
    parser.add_argument("--fail-on-reject", "-f", 
                       action="store_true",
                       help="Exit with code 2 if rejection reason is satisfied")
    parser.add_argument("--quiet", "-q", 
                       action="store_true",
                       help="Don't print any output to console")

    args = parser.parse_args()

    # Resolve paths
    log_folder = args.log_folder.resolve()
    json_file = Path(args.json_file).resolve()
    output_file = args.output.resolve()

    # Determine log file paths
    if args.base_log and args.before_log and args.after_log:
        # Manual specification overrides auto-discovery
        base_log_path = args.base_log.resolve()
        before_log_path = args.before_log.resolve()
        after_log_path = args.after_log.resolve()
        if not args.quiet:
            print(f"Using manually specified log files:")
            print(f"  Base: {base_log_path}")
            print(f"  Before: {before_log_path}")
            print(f"  After: {after_log_path}")
    elif args.auto_discover:
        # Try auto-discovery
        discovered = discover_log_files(log_folder)
        if discovered:
            base_log_path, before_log_path, after_log_path = discovered
            if not args.quiet:
                print(f"Auto-discovered log files:")
                print(f"  Base: {base_log_path}")
                print(f"  Before: {before_log_path}")
                print(f"  After: {after_log_path}")
        else:
            # Fall back to simple names
            base_log_path = log_folder / "base.log"
            before_log_path = log_folder / "before.log"
            after_log_path = log_folder / "after.log"
            if not args.quiet:
                print(f"Auto-discovery failed, using default names:")
                print(f"  Base: {base_log_path}")
                print(f"  Before: {before_log_path}")
                print(f"  After: {after_log_path}")
    else:
        # Default to simple names in log folder
        base_log_path = log_folder / "base.log"
        before_log_path = log_folder / "before.log"
        after_log_path = log_folder / "after.log"

    # Parse log files
    base_log = parse_log_file(base_log_path)
    before_log = parse_log_file(before_log_path)
    after_log = parse_log_file(after_log_path)

    # Load combined JSON
    p2p, f2p = load_combined_json(json_file)

    # Verify rules
    report = verify_rules(base_log, before_log, after_log, p2p, f2p,
                          base_log_path, before_log_path, after_log_path)

    # Format output
    pretty_json = args.pretty and not args.compact
    text = json.dumps(report, indent=2 if pretty_json else None, ensure_ascii=False)
    
    # Write to file
    output_file.write_text(text + "\n", encoding="utf-8")
    
    # Print to console unless quiet
    if not args.quiet:
        print(f"\nResults written to: {output_file}")

    # Exit with appropriate code
    if args.fail_on_reject and report["rejection_reason"]["satisfied"]:
        sys.exit(2)

if __name__ == "__main__":
    main()

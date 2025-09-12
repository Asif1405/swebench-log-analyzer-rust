# Rust Test Verification Tool

A flexible Python tool for verifying Rust test execution patterns and rules against log files. This tool analyzes test results from multiple log files (base, before, after) and validates various rules for pass-to-pass (P2P) and fail-to-pass (F2P) test transitions.

## Features

- **Dynamic Log Discovery**: Automatically finds log files with patterns like `*_base.log`, `*_before.log`, `*_after.log`
- **Enhanced Parsing**: Robust parsing of Rust test output, handling edge cases like:
  - Split status words across lines (`test name ... o\nk`)
  - Buried status words in debug output
  - Multi-line test results
  - Concatenated output patterns
- **Flexible Input Formats**: Supports both new and legacy JSON formats
- **Rule Validation**: Comprehensive verification of test transition rules
- **Silent Operation**: No console output for automated workflows

## Installation

No installation required. Just ensure you have Python 3.6+ installed.

```bash
git clone https://github.com/Asif1405/swebench-log-analyzer-rust
cd turing-logs
```

## Usage

### Basic Usage

```bash
# Auto-discover logs in current directory
python3 main.py test_data.json

# Use logs from specific folder with auto-discovery
python3 main.py --log-folder /path/to/logs test_data.json

# Specify output file
python3 main.py --output results.json test_data.json
```

### Advanced Usage

```bash
# Manually specify log files (overrides auto-discovery)
python3 main.py --base-log project_base.log --before-log project_before.log --after-log project_after.log test_data.json

# Silent operation (no console output)
python3 main.py --quiet test_data.json

# Compact JSON output
python3 main.py --compact test_data.json

# Fail on rejection
python3 main.py --fail-on-reject test_data.json
```

## Input Format

The tool accepts JSON files containing test lists in two formats:

### JSON Format (Should contain)
```json
{
  "pass_to_pass": [
    "test_module::test_function_1",
    "test_module::test_function_2"
  ],
  "fail_to_pass": [
    "test_module::test_function_3",
    "test_module::test_function_4"
  ]
}
```

## Log File Discovery

The tool automatically discovers log files using these patterns:

1. **Pattern-based discovery**: `*_base.log`, `*_before.log`, `*_after.log`
2. **Prefix matching**: Ensures consistent prefixes (e.g., `project_base.log`, `project_before.log`, `project_after.log`)
3. **Fallback**: Simple names (`base.log`, `before.log`, `after.log`)

### Example Log Structures

```
logs/
├── base.log           # Simple naming
├── before.log
└── after.log

logs/
├── myproject_base.log    # Pattern naming
├── myproject_before.log
└── myproject_after.log
```

## Rule Validation

The tool validates five key rules:

1. **C1**: Failed tests in base log should appear in P2P list
2. **C2**: Failed tests in after log should appear in F2P or P2P list
3. **C3**: F2P tests should pass in before log
4. **C4**: P2P tests missing from base log should not pass in before log
5. **C5**: No duplicate test entries within the same test file

### Enhanced Duplicate Detection (C5)

The tool correctly distinguishes between:

- **True Duplicates** (problematic): Same test appearing multiple times within the same test file - indicates framework issues, flaky tests, or re-runs
- **Legitimate Same-Named Tests** (normal): Same test name in different test files (e.g., `dfs_visit` in both `tests/graph.rs` and `tests/quickcheck.rs`) - this is perfectly normal in Rust projects
- **Legitimate Same-Named Tests** (normal): Different tests with same names from different modules/files

**Detection Logic:**
- Tests appearing close together (<20 lines) with similar contexts → Likely true duplicates
- Tests appearing far apart (>20 lines) with different contexts → Legitimate separate tests
- Common in Rust projects: `dfs_visit` in both `tests/graph.rs` and `tests/quickcheck.rs`

**Enhanced Output Example:**
```json
"c5_duplicates_in_same_log_for_F2P_or_P2P": {
  "ok": false,
  "duplicate_examples_per_log": {
    "base_info": [
      "dfs_visit (appears 2 times - different contexts)",
      "test_tarjan_scc (appears 2 times - different contexts)"
    ]
  }
}
```

## Output Format

Results are written to JSON with detailed information:

```json
{
  "inputs": {
    "base_log": "/path/to/base.log",
    "before_log": "/path/to/before.log",
    "after_log": "/path/to/after.log"
  },
  "counts": {
    "P2P": 42,
    "F2P": 2
  },
  "rule_checks": {
    "c1_failed_in_base_present_in_P2P": {
      "ok": false,
      "examples": []
    }
    // ... other rules
  },
  "rejection_reason": {
    "satisfied": false,
    "p2p_ignored_because_passed_in_base": [...],
    "p2p_considered": [...],
    "p2p_rejected": [...],
    "p2p_considered_but_ok": [...]
  },
  "debug_log_counts": [
    {
      "label": "base",
      "passed": 43,
      "failed": 0,
      "ignored": 0,
      "all": 43
    }
    // ... other logs
  ]
}
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--log-folder` | `-l` | Folder to search for log files |
| `--auto-discover` | `-a` | Enable auto-discovery (default: true) |
| `--base-log` | | Explicit path to base log file |
| `--before-log` | | Explicit path to before log file |
| `--after-log` | | Explicit path to after log file |
| `--output` | `-o` | Output JSON file (default: verify_results.json) |
| `--pretty` | `-p` | Pretty-print JSON output (default: true) |
| `--compact` | `-c` | Compact JSON output |
| `--fail-on-reject` | `-f` | Exit with code 2 if rejection satisfied |
| `--quiet` | `-q` | No console output |

## Examples

### Example 1: Basic Usage
```bash
python3 main.py rust-test-data.json
```

### Example 2: Custom Log Folder
```bash
python3 main.py --log-folder ./test_logs rust-test-data.json
```

### Example 3: Manual Log Specification
```bash
python3 main.py \
  --base-log ./logs/experiment_base.log \
  --before-log ./logs/experiment_before.log \
  --after-log ./logs/experiment_after.log \
  rust-test-data.json
```

## Parsing Capabilities

The tool handles complex Rust test output patterns:

- **Standard format**: `test module::function ... ok`
- **Split status**: `test module::function ... o\nk`
- **Buried status**: `test module::function ... [debug output] ok`
- **Multi-line results**: Status appears on separate lines
- **Concatenated output**: Test results mixed with other output

## Error Handling

- Missing log files: Clear error messages with file paths
- Invalid JSON: Detailed JSON parsing error information
- Malformed test data: Validation errors with helpful suggestions

## Development

### Project Structure
```
├── main.py                    # Main verification script
├── rust-phf__rust-phf-342.json  # Example test data
├── logs/                      # Log files directory
│   ├── base.log
│   ├── before.log
│   └── after.log
├── verify_results.json        # Output results
└── README.md                  # This file
```

### Dependencies
- Python 3.6+
- Standard library only (no external dependencies)

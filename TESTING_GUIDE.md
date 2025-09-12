# Rust Test Verification Tool - Testing Guide

## Overview

This document provides a comprehensive guide to the testing infrastructure for the Rust Test Verification Tool. The test suite covers all 5 validation rules (C1-C5) with extensive edge case testing and enhanced feature validation.

## Test Structure

```
tests/
├── __init__.py                 # Test package initialization
├── test_base.py               # Base testing utilities and fixtures
├── test_rule_c1.py           # Rule C1: Failed in base → P2P
├── test_rule_c2.py           # Rule C2: Failed in after → F2P/P2P  
├── test_rule_c3.py           # Rule C3: F2P pass in before
├── test_rule_c4.py           # Rule C4: P2P missing/not passing
├── test_rule_c5.py           # Rule C5: No same-file duplicates
└── fixtures/                 # Additional test data (optional)
```

## Running Tests

### Run All Tests
```bash
# Run all tests with verbose output
python3 -m unittest discover -s tests -p "test_*.py" -v

# Run all tests quietly
python3 -m unittest discover -s tests -p "test_*.py"
```

### Run Specific Rule Tests
```bash
# Test only Rule C1
python3 -m unittest tests.test_rule_c1 -v

# Test only Rule C5 (duplicates)
python3 -m unittest tests.test_rule_c5 -v
```

### Run Individual Test Cases
```bash
# Run a specific test method
python3 -m unittest tests.test_rule_c1.TestRuleC1.test_c1_basic_pass -v
```

## Test Infrastructure

### BaseTestCase Class
Located in `tests/test_base.py`, provides:

- **Temporary file management**: Creates and cleans up test log files
- **Log parsing utilities**: Converts content to parsed log format
- **Rule verification runner**: Executes rule validation with test data
- **Assertion helpers**: Specialized assertions for rule testing

Key methods:
```python
self.assertRulePassed(result, "rule_name")
self.assertRuleFailed(result, "rule_name")
self.assertExamplesContain(result, "rule_name", ["test1", "test2"])
self.assertRejectionSatisfied(result, expected=True)
```

### LogFixtures Class
Provides standardized log content for testing:

- `basic_passing_tests()` - Simple passing test log
- `basic_failing_tests()` - Simple failing test log
- `mixed_status_tests()` - Mixed pass/fail/ignored
- `empty_log()` - Empty test run
- `duplicate_tests_same_file()` - Same-file duplicates
- `duplicate_tests_different_files()` - Different-file same names
- `complex_test_names()` - Module paths and complex names
- `flaky_test_retry()` - Flaky test scenario
- `split_status_words()` - Split status across lines
- `buried_status()` - Status buried in debug output

## Test Coverage by Rule

### Rule C1 (12 tests)
**Purpose**: Failed tests in base log should appear in P2P list

**Test Categories**:
- ✅ Basic pass/fail scenarios
- ✅ Empty logs and lists
- ✅ Partial coverage
- ✅ Complex test names
- ✅ Case sensitivity
- ✅ Buried status parsing
- ✅ Example limiting

### Rule C2 (12 tests)
**Purpose**: Failed tests in after log should appear in F2P or P2P list

**Test Categories**:
- ✅ Pass with F2P, P2P, or mixed lists
- ✅ Empty logs and lists
- ✅ Duplicate entries in both lists
- ✅ Flaky test failures
- ✅ Regression scenarios
- ✅ Example limiting

### Rule C3 (12 tests)
**Purpose**: F2P tests should pass in before log

**Test Categories**:
- ✅ Basic pass/fail scenarios
- ✅ Empty logs and F2P lists
- ✅ Missing vs ignored tests
- ✅ New test scenarios
- ✅ Flaky test handling
- ✅ Example limiting

### Rule C4 (11 tests)
**Purpose**: P2P tests missing from base should not pass in before

**Test Categories**:
- ✅ Basic pass/fail scenarios
- ✅ Empty logs and P2P lists
- ✅ Mixed base statuses
- ✅ Multiple missing tests
- ✅ Flaky behavior
- ✅ Example limiting

### Rule C5 (14 tests)
**Purpose**: No duplicate test entries within same test file

**Test Categories**:
- ✅ Basic duplicate detection
- ✅ Same-file vs different-file duplicates
- ✅ Enhanced context analysis
- ✅ Close proximity detection
- ✅ Retry scenario detection
- ✅ Distance-based filtering
- ✅ Pattern matching variations
- ✅ Report limiting

## Edge Cases Covered

### 1. Empty Data Scenarios
- Empty log files
- Empty P2P/F2P lists
- Missing test data

### 2. Complex Test Names
- Module paths (`module::submodule::test`)
- Underscores and numbers
- Case variations

### 3. Parsing Edge Cases
- Buried status in debug output
- Split status words (`o\nk`)
- Multiple occurrences of same test
- Flaky test scenarios

### 4. Enhanced Detection
- Context-aware duplicate analysis
- Retry pattern detection
- Distance-based filtering
- Multiple pattern matching

## Adding New Tests

### 1. Choose the Appropriate Test File
- Rule-specific tests go in `test_rule_cX.py`
- General parsing tests go in `test_base.py`

### 2. Follow Naming Conventions
```python
def test_c1_specific_scenario(self):
    """Test C1 with specific edge case description"""
```

### 3. Use Standard Test Structure
```python
def test_example(self):
    # Arrange - set up test data
    base_content = LogFixtures.basic_failing_tests()
    before_content = LogFixtures.basic_passing_tests()
    after_content = LogFixtures.basic_passing_tests()
    p2p = ["test1", "test2"]
    f2p = []
    
    # Act - run the verification
    result = self.run_rule_verification(base_content, before_content, after_content, p2p, f2p)
    
    # Assert - check the results
    self.assertRulePassed(result, "c1_failed_in_base_present_in_P2P")
    self.assertExamplesContain(result, "c1_failed_in_base_present_in_P2P", ["test1"])
```

### 4. Add New Fixtures if Needed
```python
@staticmethod
def new_scenario_fixture() -> str:
    return """
Running tests/new.rs (target/debug/deps/new-123)
test new_test ... ok
test another_test ... FAILED

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
"""
```

## Debugging Test Failures

### 1. Check Rule Logic
Examine what the rule actually checks vs what the test expects:
```python
# Add debug output in tests
print("Rule result:", result["rule_checks"]["rule_name"])
print("Examples:", result["rule_checks"]["rule_name"]["examples"])
```

### 2. Check Parsing Results
Verify log parsing works correctly:
```python
from main import parse_rust_tests_text
parsed = parse_rust_tests_text(test_content)
print("Passed:", parsed["passed"])
print("Failed:", parsed["failed"])
```

### 3. Check Status Lookup
Verify status determination:
```python
from main import status_lookup
statuses = status_lookup(["test_name"], parsed_log)
print("Status:", statuses)
```

## Performance Considerations

- Tests run in ~0.16 seconds for all 67 tests
- No external dependencies required
- Temporary files are automatically cleaned up
- Memory usage is minimal due to small test fixtures

## Continuous Integration

To run tests in CI environments:

```bash
# Exit with non-zero code on test failure
python3 -m unittest discover -s tests -p "test_*.py" -v

# Check exit code
if [ $? -eq 0 ]; then
    echo "✅ All tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi
```

## Best Practices

1. **Test Independence**: Each test should be independent and not rely on others
2. **Clear Naming**: Test names should clearly describe the scenario being tested
3. **Comprehensive Coverage**: Test both positive and negative cases
4. **Edge Cases**: Include edge cases and error conditions
5. **Documentation**: Add docstrings explaining what each test validates
6. **Maintainability**: Use fixtures and utilities to avoid code duplication

## Test Maintenance

- **Adding Rules**: Create new `test_rule_cX.py` file with comprehensive coverage
- **Modifying Logic**: Update tests when rule logic changes
- **Performance**: Monitor test execution time and optimize if needed
- **Coverage**: Ensure new features have corresponding tests

---

**Total Test Coverage**: 67 comprehensive tests covering all rules and edge cases
**Success Rate**: 100% passing
**Framework**: Python unittest (built-in, no external dependencies)

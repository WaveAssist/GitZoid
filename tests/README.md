# GitZoid Test Suite

This directory contains comprehensive tests for the GitZoid assistant.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and pytest configuration
├── unit/                    # Unit tests
│   ├── test_fetch_pull_requests.py
│   ├── test_generate_review.py
│   └── test_post_comment.py
└── integration/            # Integration tests
    └── test_workflow.py
```

## Running Tests

### Install Dependencies

```bash
pip install -r tests/requirements.txt
```

### Run All Tests

```bash
pytest
```

### Run Specific Test File

```bash
pytest tests/unit/test_fetch_pull_requests.py
```

### Run with Coverage

```bash
pytest --cov=. --cov-report=html
```

### Run Specific Test

```bash
pytest tests/unit/test_fetch_pull_requests.py::TestIsBotPR::test_is_bot_pr_by_type
```

## Test Categories

### Unit Tests

Unit tests focus on individual functions with mocked dependencies:

- **fetch_pull_requests.py**: Tests for PR fetching, filtering, and state management
- **generate_review.py**: Tests for prompt generation and file formatting
- **post_comment.py**: Tests for comment formatting and posting

### Integration Tests

Integration tests verify the complete workflow with mocked external APIs:

- Complete fetch → generate → post workflow
- Incremental review detection and processing
- First run behavior
- Error handling across the workflow

## Mocking Strategy

All external dependencies are mocked:

- **GitHub API**: `requests.get` and `requests.post` are mocked
- **WaveAssist SDK**: `waveassist` module functions are mocked
- **LLM Calls**: `waveassist.call_llm()` returns mock structured responses

## Test Coverage

The test suite covers:

- ✅ Pure functions (no mocks needed)
- ✅ Functions with external API calls (mocked)
- ✅ Error handling and edge cases
- ✅ Data validation and transformation
- ✅ State management (reviewed_prs tracker)
- ✅ Business logic (first run, incremental reviews, filtering)

## Writing New Tests

When adding new tests:

1. Use fixtures from `conftest.py` for common test data
2. Mock external dependencies using `@patch` decorator
3. Follow naming convention: `test_<function_name>_<scenario>`
4. Group related tests in classes: `Test<FunctionName>`
5. Add docstrings explaining what each test verifies

## Example Test

```python
@patch('fetch_pull_requests.requests.get')
def test_fetch_compare_diff_success(self, mock_get, sample_compare_response):
    """Test successfully fetching compare diff."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = sample_compare_response
    mock_get.return_value = mock_response

    headers = {"Authorization": "token fake_token"}
    result = fetch_compare_diff("owner/repo", "base123", "head456", headers)

    assert len(result) == 1
    assert result[0]["filename"] == "modified.py"
```

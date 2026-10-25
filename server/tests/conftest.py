import pytest

from app import security


@pytest.fixture(autouse=True)
def _fresh_rate_limit():
    """The rate limiter's counter is module-level state shared by every test client. A test that sends many requests must not
    leave it full for the next test, so it is emptied before and after each one."""
    security._BUCKETS.clear()
    yield
    security._BUCKETS.clear()

"""Reset the registry around every test so registrations don't leak."""

import pytest

from mimedet import reset_registry


@pytest.fixture(autouse=True)
def _reset_registry() -> None:
    reset_registry()
    yield
    reset_registry()

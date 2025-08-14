import pytest
import logging

@pytest.fixture(autouse=True)
def setup_logging():
    """Настройка логирования для тестов."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
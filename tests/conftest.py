import pytest

from dyepack.attacks import load_attacks
from dyepack.tasks import TASKS


@pytest.fixture
def tasks():
    return {t.id: t for t in TASKS}


@pytest.fixture
def attacks():
    return load_attacks()
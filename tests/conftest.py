import pytest

from tripwire.attacks import load_attacks
from tripwire.tasks import TASKS


@pytest.fixture
def tasks():
    return {t.id: t for t in TASKS}


@pytest.fixture
def attacks():
    return load_attacks()
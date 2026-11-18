import pytest

from taintline.attacks import load_attacks
from taintline.tasks import TASKS


@pytest.fixture
def tasks():
    return {t.id: t for t in TASKS}


@pytest.fixture
def attacks():
    return load_attacks()
import pytest

from llmsec.catalog import load_catalog
from runner import run_benchmark


@pytest.fixture(scope="session")
def cases():
    return load_catalog()


@pytest.fixture(scope="session")
def benchmark(cases):
    return run_benchmark(cases)

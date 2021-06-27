import pytest

from pykdebugparser.trace_codes import default_trace_codes
from pykdebugparser.traces_parser import TracesParser


@pytest.fixture(scope='session')
def traces_parser():
    return TracesParser(default_trace_codes(), {})

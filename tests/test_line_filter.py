import random
import re

import pytest

from pykdebugparser.highlight import highlight
from pykdebugparser.line_filter import LineFilter, emphasize

LINE = 'ls(1)  open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3'
SGR = re.compile(r'\x1b\[[0-9;]*m')


def _emphasized(text):
    """Which characters of the plain text are emphasized."""
    on = False
    chars = []
    for part in re.split(r'(\x1b\[[0-9;]*m)', text):
        if part.startswith('\x1b['):
            on = True if part == '\x1b[1;4m' else (False if part == '\x1b[0m' else on)
        else:
            chars += [on] * len(part)
    return chars


@pytest.mark.parametrize('kwargs, kept', [
    ({}, True),
    ({'match': ['xpcproxy', 'O_RDONLY']}, True),
    # Every --match must be in the line.
    ({'match': ['xpcproxy', 'O_WRONLY']}, False),
    ({'match': ['XPCPROXY']}, False),
    ({'match_insensitive': ['XPCPROXY']}, True),
    ({'invert_match': ['ls(']}, False),
    ({'invert_match': ['LS(']}, True),
    ({'invert_match_insensitive': ['LS(']}, False),
    # Any --regex is enough.
    ({'regex': ['nope', r'fd: \d']}, True),
    ({'regex': ['nope']}, False),
    ({'insensitive_regex': ['XPC.*RDONLY']}, True),
    ({'match': ['open'], 'invert_match': ['xpcproxy']}, False),
])
def test_keep(kwargs, kept):
    line_filter = LineFilter(**kwargs)
    assert line_filter.keep(LINE) == kept
    assert (line_filter.kept_spans(LINE) is not None) == kept


def test_bool():
    assert not LineFilter()
    assert LineFilter(invert_match=['x'])


def test_spans():
    line_filter = LineFilter(match=['xpcproxy'], match_insensitive=['o_rdonly'], regex=[r'fd: \d'])
    assert line_filter.spans(LINE) == [(26, 34), (37, 45), (48, 53)]
    assert line_filter.kept_spans(LINE) == [(26, 34), (37, 45), (48, 53)]
    # Every occurrence, like re.finditer.
    assert LineFilter(match=['o']).spans('foo boo') == [(1, 2), (2, 3), (5, 6), (6, 7)]


def test_emphasize_plain_and_colored():
    spans = [(26, 34), (37, 45)]
    assert emphasize(LINE, spans) == \
        'ls(1)  open("/usr/libexec/\x1b[1;4mxpcproxy\x1b[0m", \x1b[1;4mO_RDONLY\x1b[0m), fd: 3'
    colored = emphasize('ls(1)  ' + highlight(LINE[7:]), spans)
    assert SGR.sub('', colored) == LINE
    # The string's color resumes after the emphasized part.
    assert '\x1b[32m"/usr/libexec/\x1b[1;4mxpcproxy\x1b[0m\x1b[32m"' in colored
    assert emphasize(LINE, []) == LINE


def test_emphasize_exactly_the_spans():
    random.seed(1)
    for _ in range(2000):
        plain = ''.join(random.choice('ab "(),:0x12') for _ in range(random.randint(0, 40)))
        text = highlight(plain) if random.random() < 0.7 else plain
        spans = []
        for _ in range(random.randint(0, 4)):
            start = random.randint(0, len(plain))
            end = random.randint(start, len(plain))
            if end > start:
                spans.append((start, end))
        out = emphasize(text, spans)
        assert SGR.sub('', out) == plain
        assert _emphasized(out) == [any(start <= i < end for start, end in spans) for i in range(len(plain))]

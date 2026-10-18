import re

import pytest
from pygments import highlight as pygments_highlight

from pykdebugparser import highlight


@pytest.mark.parametrize('line', [
    # The tokenizer's own lines.
    'read(7, 0x11bf1c000, 25558), count: 25558',
    'open("/private/var/x", O_RDONLY | O_CLOEXEC), fd: 3',
    'open_nocancel("/System/Library/Foundation.framework//en.lproj", O_RDONLY), errno: ENOENT(2)',
    'lookup(".tmp.OgDV0NXsrZ"), vnode id: 8638794530369352533',
    'workq_kernreturn(256, 0x16d2c2b80, 1, 0), return: 0',
    'sigreturn(0x16bd56ec8, 30, 0x17fcd6aa5d512e6c), errno: EJUSTRETURN(-2)',
    'pread(12, 0xad80793d2, 4096, 0x31e000), count: 4096',
    'getxattr("", NULL, 0x0, 0, int, true), size: 0x10',
    'thread_suspend, tid: 55996, user_stop_count: 0, pidsuspended: True',
    'mmap(0x0, 0755, 0b101, 10u, 3LL), count: 0x8e0000',
    'DBG_DYLD_TIMING_OBJC_MAP',
    # Lines left to pygments.
    "ioctl(8, 0xc020699d /* _IOC(IOC_IN | IOC_OUT, 'i', 157, 32) */, 0x16d3cbea0)",
    'TRACE_LOST_EVENTS: the kernel dropped trace events here',
    'stat64("/private/var/Snapshots/com.apple.AppStore - {DEFAULT GROUP}", 0x16db399d0)',
    'open("a\\"b"), fd: 3',
    'struct x, case 1, L"wide", u8"x"',
    'duration: 1.5, 2e10, .5, 3f, 7l',
    'mixed $dollar # hash',
])
def test_highlight_renders_like_pygments(line):
    assert _render(highlight.highlight(line)) == _render(
        pygments_highlight(line, highlight.c_lexer, highlight.color_formatter).strip())


def test_highlight_uses_fewer_escape_sequences():
    line = 'read(7, 0x11bf1c000, 25558), count: 25558'
    assert len(highlight.highlight(line)) < len(pygments_highlight(line, highlight.c_lexer,
                                                                   highlight.color_formatter).strip()) / 2


_SGR = re.compile(r'\x1b\[([0-9;]*)m')


def _render(text):
    """Each character with the terminal attributes it shows (a space shows only its background)."""
    fg = bg = None
    bold = italic = False
    cells = []
    pos = 0
    for match in _SGR.finditer(text):
        cells += [(char, fg, bg, bold, italic) for char in text[pos:match.start()]]
        pos = match.end()
        codes = [int(code) for code in match.group(1).split(';') if code] or [0]
        i = 0
        while i < len(codes):
            code = codes[i]
            if code == 0:
                fg = bg = None
                bold = italic = False
            elif code == 1:
                bold = True
            elif code == 3:
                italic = True
            elif code == 39:
                fg = None
            elif code == 49:
                bg = None
            elif code in (38, 48) and codes[i + 1] == 2:
                if code == 38:
                    fg = tuple(codes[i + 2:i + 5])
                else:
                    bg = tuple(codes[i + 2:i + 5])
                i += 4
            else:
                raise ValueError(f'unexpected SGR code {code}')
            i += 1
    cells += [(char, fg, bg, bold, italic) for char in text[pos:]]
    return [(char, None, bg, False, False) if char == ' ' else (char, fg, bg, bold, italic)
            for char, fg, bg, bold, italic in cells]

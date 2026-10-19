import re

import pytest

from pykdebugparser.highlight import highlight

_SGR = re.compile(r'\x1b\[[0-9;]*m')

DIM, RESET = '\x1b[2m', '\x1b[0m'
RED, GREEN, YELLOW, BLUE, CYAN = '\x1b[31m', '\x1b[32m', '\x1b[33m', '\x1b[34m', '\x1b[36m'


def _colored(color, text):
    return color + text + RESET


@pytest.mark.parametrize('line, expected', [
    ('open("/etc/hosts", O_RDONLY | O_CLOEXEC), fd: 3',
     f'{_colored(BLUE, "open")}({_colored(GREEN, chr(34) + "/etc/hosts" + chr(34))}, {_colored(YELLOW, "O_RDONLY")} | '
     f'{_colored(YELLOW, "O_CLOEXEC")}), {_colored(DIM, "fd:")} {_colored(CYAN, "3")}'),
    ('stat64("/x"), errno: ENOENT(2)',
     f'{_colored(BLUE, "stat64")}({_colored(GREEN, chr(34) + "/x" + chr(34))}), {_colored(RED, "errno:")} '
     f'{_colored(RED, "ENOENT")}({_colored(RED, "2")})'),
    ('task_for_pid(515, 97997, 0x16bd572fc), result: KERN_SUCCESS',
     f'{_colored(BLUE, "task_for_pid")}({_colored(CYAN, "515")}, {_colored(CYAN, "97997")}, '
     f'{_colored(CYAN, "0x16bd572fc")}), {_colored(DIM, "result:")} {_colored(YELLOW, "KERN_SUCCESS")}'),
    ('mach_port_mod_refs(1, 0x0, MACH_PORT_RIGHT_SEND, 1), result: KERN_INVALID_RIGHT',
     f'{_colored(BLUE, "mach_port_mod_refs")}({_colored(CYAN, "1")}, {_colored(CYAN, "0x0")}, '
     f'{_colored(YELLOW, "MACH_PORT_RIGHT_SEND")}, {_colored(CYAN, "1")}), {_colored(DIM, "result:")} '
     f'{_colored(RED, "KERN_INVALID_RIGHT")}'),
    ('lookup("private/var/db"), vnode id: 42',
     f'{_colored(BLUE, "lookup")}({_colored(GREEN, chr(34) + "private/var/db" + chr(34))}), '
     f'{_colored(DIM, "vnode id:")} {_colored(CYAN, "42")}'),
    ('sigreturn(0x1, 30, 0x2), errno: EJUSTRETURN(-2)',
     f'{_colored(BLUE, "sigreturn")}({_colored(CYAN, "0x1")}, {_colored(CYAN, "30")}, {_colored(CYAN, "0x2")}), '
     f'{_colored(RED, "errno:")} {_colored(RED, "EJUSTRETURN")}({_colored(RED, "-2")})'),
    ('DBG_DYLD_TIMING_OBJC_MAP', _colored(BLUE, 'DBG_DYLD_TIMING_OBJC_MAP')),
])
def test_highlight(line, expected):
    assert highlight(line) == expected


@pytest.mark.parametrize('line', [
    'open("/etc/hosts", O_RDONLY), fd: 3',
    "ioctl(8, 0xc020699d /* _IOC(IOC_IN | IOC_OUT, 'i', 157, 32) */, 0x16d3cbea0)",
    'TRACE_LOST_EVENTS: the kernel dropped trace events here',
    'stat64("/a b/{c}: d", 0x1), count: 0x10',
    'unterminated "string',
    '',
])
def test_highlight_keeps_the_text(line):
    assert _SGR.sub('', highlight(line)) == line

"""Syntax highlighting of trace lines, such as `open("/etc/hosts", O_RDONLY), fd: 3`.

Lines are colored with the terminal's 16 basic colors, so they follow its theme:

- the call or event name at the start, blue (not bold: on a dark theme bold reads as bright white);
- strings (paths, symbols, ...), green;
- numbers, cyan;
- constants (flags, enums, signals: `O_RDONLY`, `KERN_SUCCESS`, `SIGKILL`), yellow;
- an error (`errno: ENOENT(2)`, a `KERN_*` failure), red;
- the labels of results and fields (`fd:`, `count:`), dim.

A trace is mostly the same calls with the same arguments, so the most recent lines are cached.
"""
import re
from functools import lru_cache

_RESET = '\x1b[0m'
_DIM = '\x1b[2m'
_RED = '\x1b[31m'
_GREEN = '\x1b[32m'
_YELLOW = '\x1b[33m'
_BLUE = '\x1b[34m'
_CYAN = '\x1b[36m'

_TOKEN = re.compile(
    r'(?P<string>"[^"]*")'
    r'|(?P<number>-?0[xX][0-9a-fA-F]+|-?\d+)'
    r'|(?P<label>[A-Za-z_][\w ]*?:)(?= |$)'
    r'|(?P<name>[A-Za-z_]\w*)'
)
# A constant is all capitals, digits and underscores, with at least one capital.
_CONSTANT = re.compile(r'[A-Z][A-Z0-9_]*')
# `KERN_SUCCESS` is a result, not an error.
_SUCCESS = {'KERN_SUCCESS'}


@lru_cache(maxsize=1 << 14)
def highlight(text: str) -> str:
    """`text` with terminal colors (SGR escape sequences); the text itself is unchanged."""
    out = []
    pos = 0
    error = False  # inside the value of an `errno:` result
    first = True
    for match in _TOKEN.finditer(text):
        if match.start() > pos:
            out.append(text[pos:match.start()])
        pos = match.end()
        kind = match.lastgroup
        value = match.group()
        if kind == 'string':
            out.append(_GREEN + value + _RESET)
        elif kind == 'number':
            out.append((_RED if error else _CYAN) + value + _RESET)
        elif kind == 'label':
            error = value == 'errno:'
            out.append((_RED if error else _DIM) + value + _RESET)
        elif first:
            out.append(_BLUE + value + _RESET)
        elif _CONSTANT.fullmatch(value):
            failed = error or (value.startswith('KERN_') and value not in _SUCCESS)
            out.append((_RED if failed else _YELLOW) + value + _RESET)
        else:
            out.append(value)
        first = False
    out.append(text[pos:])
    return ''.join(out)

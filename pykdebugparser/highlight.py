"""Syntax highlighting of trace lines, as pygments' C lexer and `stata-dark` true color formatter do it.

pygments lexes each line through a general state machine, which formats about 19k lines/s: too slow for a live
trace. Trace lines use a small part of C's syntax, so `highlight` tokenizes them with one regular expression that
follows the same rules, and produces the same escape sequences. A line with anything outside that part (a label at its
start, `;` or `{`, comments, character literals, string escapes, floating-point numbers, ...) goes to pygments, so the
result is always pygments' own.
"""
import re
from functools import lru_cache

from pygments import highlight as pygments_highlight
from pygments import lexers
from pygments.formatters import TerminalTrueColorFormatter
from pygments.token import Keyword, Name, Number, Operator, Punctuation, String, Whitespace

c_lexer = lexers.CLexer()
color_formatter = TerminalTrueColorFormatter(style='stata-dark')

# pygments.lexers.c_cpp.CFamilyLexer's 'keywords', 'types' and builtins, the names it does not lex as `Name`.
_KEYWORDS = {
    'asm', 'auto', 'break', 'const', 'constexpr', 'continue', 'countof', 'default', 'defer', 'do', 'else', 'enum',
    'extern', 'for', 'goto', 'if', 'register', 'restricted', 'return', 'sizeof', 'static', 'switch', 'typedef',
    'typeof', 'typeof_unqual', 'volatile', 'while', 'thread_local', 'alignas', 'alignof', 'static_assert', '_Pragma',
    'fortran',
}
_RESERVED = {'inline', '_inline', '__inline', 'naked', 'restrict', 'thread', '__int8', '__int16', '__int32',
             '__int64', '__wchar_t', '__m128i', '__m128d', '__m128', '__m64'} | {
    '__' + name for name in ('asm', 'based', 'except', 'stdcall', 'cdecl', 'fastcall', 'declspec', 'finally', 'try',
                             'leave', 'w64', 'unaligned', 'raise', 'noop', 'identifier', 'forceinline', 'assume',
                             'null')}
_TYPES = {'bool', 'int', 'long', 'float', 'short', 'double', 'char', 'unsigned', 'signed', 'void', '_BitInt',
          '__int128'}
_BUILTINS = {'true', 'false', 'NULL', 'nullptr'}
# Names that start another lexer state, or a string with an affix (`L"..."`): left to pygments.
_STATEFUL = {'struct', 'union', 'case', 'L', 'u', 'U', 'u8'}

_INT_SUFFIX = r'(?:[uU][lL]{0,2}|[lL]{1,2}[uU]?)?'
_DEC = r'\d(?:\'?\d)*'
_HEX = r'[0-9a-fA-F](?:\'?[0-9a-fA-F])*'
# The alternatives are tried in the lexer's order at each token start. `unsupported` marks what pygments lexes
# differently from this tokenizer (comments and floating-point numbers); characters no alternative matches (`'`, `\\`,
# `#`, `$`, a string with an escape, ...) also send the line to pygments.
_TOKEN = re.compile(
    r'(?P<unsupported>/[/*]'
    r'|0[xX](?:' + _HEX + r'\.' + _HEX + r'|\.' + _HEX + r'|' + _HEX + r')[pP]'
    r'|-?(?:' + _DEC + r'\.' + _DEC + r'|\.' + _DEC + r'|' + _DEC + r')[eE][+-]?' + _DEC +
    r'|-?(?:' + _DEC + r'\.|\.' + _DEC + r'|' + _DEC + r'[fFlL])'
    r')'
    r'|(?P<string>")(?P<content>[^\\"\n]*)(?P<close>")'
    r'|(?P<hex>-?0[xX]' + _HEX + _INT_SUFFIX + r')'
    r'|(?P<bin>-?0[bB][01](?:\'?[01])*' + _INT_SUFFIX + r')'
    r'|(?P<oct>-?0(?:\'?[0-7])+' + _INT_SUFFIX + r')'
    r'|(?P<int>-?' + _DEC + _INT_SUFFIX + r')'
    r'|(?P<op>[~!%^&*+=|?:<>/-])'
    r'|(?P<punct>[()\[\],.])'
    r'|(?P<name>[a-zA-Z_]\w*)'
    r'|(?P<ws>[^\S\n]+)'
)
# Whole-line rules of the lexer: a label at the start of a line, and functions (their rules need a `;` or `{`).
_UNSUPPORTED = re.compile(r'^\s*[a-zA-Z_$]\w*\s*:(?!:)|[;{]')


def _style(ttype):
    # The formatter uses the style of the token type, or of its closest parent that has one.
    while str(ttype) not in color_formatter.style_string and ttype.parent is not None:
        ttype = ttype.parent
    return color_formatter.style_string.get(str(ttype), ('', ''))


_GROUPS = {'hex': _style(Number.Hex), 'bin': _style(Number.Bin), 'oct': _style(Number.Oct),
           'int': _style(Number.Integer), 'op': _style(Operator), 'punct': _style(Punctuation)}
_NAME_STYLES = {}
for _names, _ttype in ((_KEYWORDS, Keyword), (_RESERVED, Keyword.Reserved), (_TYPES, Keyword.Type),
                       (_BUILTINS, Name.Builtin)):
    for _name in _names:
        _NAME_STYLES[_name] = _style(_ttype)
_NAME = _style(Name)
_STRING = _style(String)
# Whitespace only gets a foreground color, which a space does not show: it can stay in the style before it.
_FG_RESET = '\x1b[39m'
assert _style(Whitespace)[1] == _FG_RESET


def _pygments(text: str) -> str:
    return pygments_highlight(text, c_lexer, color_formatter).strip()


# Traces repeat (the same calls with the same arguments): in a busy `--bsc` trace, 77% of the lines were among the
# 16k most recent ones.
@lru_cache(maxsize=1 << 14)
def highlight(text: str) -> str:
    """`text` colored as `pygments.highlight(text, CLexer(), TerminalTrueColorFormatter('stata-dark'))` shows it.

    pygments starts and ends the escape sequence of every token, even between tokens of the same color, and colors
    spaces. Here a sequence starts only where the color changes, which renders the same in about half the bytes (the
    terminal is the bottleneck of a busy trace).
    """
    if _UNSUPPORTED.search(text):
        return _pygments(text)
    out = []
    style = None  # the (on, off) in effect
    pos = 0
    for match in _TOKEN.finditer(text):
        if match.start() != pos:
            return _pygments(text)
        pos = match.end()
        kind = match.lastgroup
        if kind == 'ws':
            out.append(match.group())
            continue
        if kind == 'unsupported':
            return _pygments(text)
        if kind == 'close':
            token_style = _STRING
        elif kind == 'name':
            name = match.group()
            if name in _STATEFUL:
                return _pygments(text)
            token_style = _NAME_STYLES.get(name, _NAME)
        else:
            token_style = _GROUPS[kind]
        if style is None or token_style[0] != style[0]:
            # Ending a foreground color is not needed when the next one replaces it.
            if style is not None and style[1] != _FG_RESET:
                out.append(style[1])
            out.append(token_style[0])
            style = token_style
        out.append(match.group())
    if pos != len(text):
        return _pygments(text)
    if style is not None:
        out.append(style[1])
    return ''.join(out).strip()

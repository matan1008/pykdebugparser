"""
Text filters of printed lines, with the matched parts highlighted, like pymobiledevice3's `syslog live` (`-m`, `-v`,
`-mi`, `-vi` and regexes). Shared by pykdebugparser's and pymobiledevice3's `parse-live`.
"""
import re
from typing import Iterable, List, Optional, Tuple

# Bold and underlined, as `syslog live` highlights its matches.
_EMPHASIS = '\x1b[1;4m'
_RESET = '\x1b[0m'
_SGR = re.compile(r'(\x1b\[[0-9;]*m)')

# The help of the options of each `LineFilter` argument, the same in both tools. The filters match the printed line:
# time, thread, process and event.
MATCH_HELP = {
    'match': 'Only print the traces containing this text, highlighted (repeatable; all must match).',
    'invert_match': 'Only print the traces not containing this text (repeatable; any match excludes).',
    'match_insensitive': 'Like --match, ignoring case.',
    'invert_match_insensitive': 'Like --invert-match, ignoring case.',
    'regex': 'Only print the traces matching this regex, highlighted (repeatable; any match includes).',
    'insensitive_regex': 'Like --regex, ignoring case.',
}


class LineFilter:
    """
    Which lines to keep, by the text they contain:

    - `match`: every one must be in the line (case-sensitive), `match_insensitive` likewise, ignoring case;
    - `invert_match`: none may be in the line, `invert_match_insensitive` likewise, ignoring case;
    - `regex`: at least one must match the line, when any is given; `insensitive_regex` likewise, ignoring case.
    """

    def __init__(self, match: Iterable[str] = (), invert_match: Iterable[str] = (),
                 match_insensitive: Iterable[str] = (), invert_match_insensitive: Iterable[str] = (),
                 regex: Iterable[str] = (), insensitive_regex: Iterable[str] = ()):
        self.match = list(match)
        self.invert_match = list(invert_match)
        self.match_insensitive = [m.lower() for m in match_insensitive]
        self.invert_match_insensitive = [m.lower() for m in invert_match_insensitive]
        self.regexes = [re.compile(r, re.DOTALL) for r in regex]
        self.regexes += [re.compile(r, re.IGNORECASE | re.DOTALL) for r in insensitive_regex]
        self._match_insensitive = [re.compile(re.escape(m), re.IGNORECASE) for m in self.match_insensitive]

    def __bool__(self) -> bool:
        return bool(self.match or self.invert_match or self.match_insensitive or self.invert_match_insensitive
                    or self.regexes)

    def keep(self, line: str) -> bool:
        """Whether to keep a line (its plain text, without colors)."""
        for m in self.invert_match:
            if m in line:
                return False
        for m in self.match:
            if m not in line:
                return False
        if self.match_insensitive or self.invert_match_insensitive:
            lower = line.lower()
            for m in self.invert_match_insensitive:
                if m in lower:
                    return False
            for m in self.match_insensitive:
                if m not in lower:
                    return False
        return not self.regexes or any(regex.search(line) for regex in self.regexes)

    def spans(self, line: str) -> List[Tuple[int, int]]:
        """The `(start, end)` of every hit of the match filters in a plain line, sorted."""
        return self._spans(line, line.lower() if self.match_insensitive else line)

    def kept_spans(self, line: str) -> Optional[List[Tuple[int, int]]]:
        """`spans` of a plain line if it is kept, `None` otherwise (in one pass)."""
        lower = line.lower() if self.match_insensitive or self.invert_match_insensitive else line
        for m in self.invert_match:
            if m in line:
                return None
        for m in self.invert_match_insensitive:
            if m in lower:
                return None
        for m in self.match:
            if m not in line:
                return None
        for m in self.match_insensitive:
            if m not in lower:
                return None
        if self.regexes and not any(regex.search(line) for regex in self.regexes):
            return None
        return self._spans(line, lower)

    def _spans(self, line: str, lower: str) -> List[Tuple[int, int]]:
        spans = [span for m in self.match for span in _find_all(line, m)]
        if self.match_insensitive:
            if len(lower) == len(line):
                spans += [span for m in self.match_insensitive for span in _find_all(lower, m)]
            else:
                # Lowering changed the length (such as 'İ'), so the offsets in `lower` don't apply to `line`.
                spans += [hit.span() for pattern in self._match_insensitive for hit in pattern.finditer(line)]
        for regex in self.regexes:
            spans += [hit.span() for hit in regex.finditer(line) if hit.end() > hit.start()]
        spans.sort()
        return spans


def _find_all(text: str, sub: str) -> List[Tuple[int, int]]:
    """The `(start, end)` of the non-overlapping occurrences of `sub` in `text`."""
    spans = []
    if not sub:
        return spans
    index = text.find(sub)
    while index != -1:
        spans.append((index, index + len(sub)))
        index = text.find(sub, index + len(sub))
    return spans


def emphasize(text: str, spans: List[Tuple[int, int]]) -> str:
    """
    Make parts of a line bold and underlined.
    :param text: The line, possibly colored with SGR escape sequences.
    :param spans: The `(start, end)` of the parts, in the line without its escape sequences (see `LineFilter.spans`).
    :return: The line with the parts emphasized, keeping its colors.
    """
    if not spans:
        return text
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if '\x1b' not in text:
        out = []
        pos = 0
        for start, end in merged:
            out += [text[pos:start], _EMPHASIS, text[start:end], _RESET]
            pos = end
        out.append(text[pos:])
        return ''.join(out)
    out = []
    # The escape sequences in effect since the last reset, restored after an emphasized part ends.
    active = ''
    inside = False
    # The emphasis is written before the next text that needs it, so a reset right before a part ends costs nothing.
    pending = False
    pos = 0  # in the plain line
    span = 0
    for part in _SGR.split(text):
        if not part:
            continue
        if part.startswith('\x1b['):
            out.append(part)
            if part in (_RESET, '\x1b[m'):
                active = ''
                pending = inside
            else:
                active += part
            continue
        offset = 0
        while offset < len(part):
            boundary = len(part)
            if span < len(merged):
                boundary = min(boundary, (merged[span][1] if inside else merged[span][0]) - pos)
            if boundary > offset:
                if pending:
                    out.append(_EMPHASIS)
                    pending = False
                out.append(part[offset:boundary])
                offset = boundary
            if offset == len(part):
                break
            if inside:
                if not pending:
                    out.append(_RESET + active)
                pending = False
                span += 1
            else:
                pending = True
            inside = not inside
        pos += len(part)
    if inside and not pending:
        out.append(_RESET + active)
    return ''.join(out)

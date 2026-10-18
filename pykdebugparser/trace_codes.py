from typing import Iterable, Mapping, Optional, Set
from pathlib import Path


def from_trace_codes_text(codes_text: str) -> Mapping[int, str]:
    """
    Convert a trace codes text to dictionary.
    :param codes_text: Trace codes file data.
    :return: Mapping between code and event name.
    """
    return {int(s[0], 16): s[1] for s in map(lambda l: l.split(), codes_text.splitlines())}


def from_trace_codes_file(path: str) -> Mapping[int, str]:
    """
    Read trace codes from a file.
    :param path: Trace codes file path.
    :return: Mapping between code and event name.
    """
    with open(path, 'r') as fd:
        return from_trace_codes_text(fd.read())


def default_trace_codes() -> Mapping[int, str]:
    """
    Get the default trace codes mapping.
    :return: Mapping between code and event name.
    """
    with open(Path(__file__).resolve().parent.joinpath('trace.codes'), 'r') as fd:
        return from_trace_codes_text(fd.read())


def syscall_eventids(names: Iterable[str], trace_codes: Optional[Mapping[int, str]] = None) -> Set[int]:
    """
    Get the event ids of BSD syscalls by name, for `PyKdebugParser.filter_eventid`.
    A name also matches its `_nocancel` variant (e.g. `open` gives `BSC_open` and `BSC_open_nocancel`).
    :param names: Syscall names, such as `open` or `openat`.
    :param trace_codes: Mapping between code and event name; the default trace codes if omitted.
    :return: The event ids.
    :raises ValueError: A name is not a known syscall.
    """
    codes = {name: code for code, name in (default_trace_codes() if trace_codes is None else trace_codes).items()}
    eventids = set()
    unknown = []
    for name in names:
        matches = {codes[event] for event in (f'BSC_{name}', f'BSC_{name}_nocancel') if event in codes}
        if not matches:
            unknown.append(name)
        eventids |= matches
    if unknown:
        raise ValueError(f'unknown syscalls: {", ".join(unknown)}')
    return eventids

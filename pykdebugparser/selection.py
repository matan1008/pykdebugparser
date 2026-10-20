"""
What `parse-live` prints for its options, shared by pykdebugparser's `parse-live` (this Mac) and pymobiledevice3's
(a device), so both select the same events the same way.
"""
import dataclasses
from typing import Iterable, List, Mapping, Set

from pykdebugparser.trace_codes import EVENT_GROUP_PREFIXES, SYSCALL_GROUPS, default_trace_codes, event_eventids, \
    group_events, group_mach_traps, parsed_events, syscall_eventids

# Subclass of the BSD syscalls (`--bsc`).
BSC_SUBCLASS = 0x040c
DBG_DYLD = 0x1f

# The help of each group's option, such as `--fs`.
GROUP_HELP: Mapping[str, str] = {
    'fs': 'The syscalls that take a path.',
    'net': 'The socket syscalls.',
    'proc': 'The process lifecycle syscalls.',
    'io': 'The syscalls on file descriptors: read, write, ...',
    'mem': 'The memory mapping syscalls and Mach traps.',
    'signal': 'The signal syscalls.',
    'cred': 'Credential, code signing and policy checks, and access to other tasks.',
    'sync': 'Locks, condition variables, kqueues and workqueues.',
    'mach': 'The Mach traps.',
    'xpc': 'libxpc events: messages sent and received, replies, transactions.',
    'dispatch': 'libdispatch events: Mach messages received through dispatch, queue misuse.',
    'runloop': 'CoreFoundation run loop events: iterations, waits, sources, timers, observers and blocks.',
}
# Every group, in the order of their options.
GROUPS = (*SYSCALL_GROUPS, *EVENT_GROUP_PREFIXES)


@dataclasses.dataclass
class Selection:
    """What parse-live prints: the events selected by id, and the parsed events of the selected classes/subclasses."""

    classes: List[int]
    subclasses: List[int]
    syscall_ids: Set[int]
    event_ids: Set[int]

    @property
    def eventids(self) -> Set[int]:
        return self.syscall_ids | self.event_ids


def parse_live_selection(*, bsc: bool = False, class_filters: Iterable[int] = (), subclass_filters: Iterable[int] = (),
                         syscalls: Iterable[str] = (), events: Iterable[str] = (), groups: Iterable[str] = (),
                         dyld: bool = False) -> Selection:
    """
    Get the events parse-live prints for its options. Everything adds up: groups add their syscalls, Mach traps and
    user space events.
    :raises ValueError: An unknown syscall or event name.
    """
    groups = list(groups)
    syscall_groups = [group for group in groups if group in SYSCALL_GROUPS]
    event_groups = [group for group in groups if group in EVENT_GROUP_PREFIXES]
    syscall_ids = syscall_eventids([*syscalls, *(name for group in syscall_groups for name in SYSCALL_GROUPS[group])])
    event_ids = event_eventids([
        *events,
        *(name for group in syscall_groups for name in group_mach_traps(group)),
        *(name for group in event_groups for name in group_events(group)),
    ])
    return Selection(classes=[*class_filters, *([DBG_DYLD] if dyld else [])],
                     subclasses=[*subclass_filters, *([BSC_SUBCLASS] if bsc else [])],
                     syscall_ids=syscall_ids, event_ids=event_ids)


def captured_events(selection: Selection) -> List[str]:
    """
    Get the names of the events parse-live prints for a selection: those selected by id (printed even without a
    decoder), and those of the selected classes and subclasses pykdebugparser decodes (the others are dropped).
    """
    parsed = parsed_events()
    eventids = selection.eventids
    return sorted({
        name for eventid, name in default_trace_codes().items()
        if eventid in eventids
        or ((eventid >> 24 in selection.classes or eventid >> 16 in selection.subclasses) and name in parsed)
    })

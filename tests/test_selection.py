import pytest

from pykdebugparser.selection import BSC_SUBCLASS, DBG_DYLD, GROUP_HELP, GROUPS, captured_events, \
    parse_live_selection
from pykdebugparser.trace_codes import SYSCALL_GROUPS, event_eventids, group_events, group_mach_traps, \
    syscall_eventids


def test_groups_have_help():
    assert set(GROUP_HELP) == set(GROUPS)


def test_selection_adds_up():
    selection = parse_live_selection(bsc=True, class_filters=[0x31], subclass_filters=[0x2b01], syscalls=['read'],
                                     events=['DBG_DYLD_TIMING_DLSYM'], groups=['mem', 'xpc'], dyld=True)
    assert selection.classes == [0x31, DBG_DYLD]
    assert selection.subclasses == [0x2b01, BSC_SUBCLASS]
    assert selection.syscall_ids == syscall_eventids(['read', *SYSCALL_GROUPS['mem']])
    assert selection.event_ids == event_eventids(['DBG_DYLD_TIMING_DLSYM', *group_mach_traps('mem'),
                                                  *group_events('xpc')])
    assert selection.eventids == selection.syscall_ids | selection.event_ids


def test_empty_selection():
    selection = parse_live_selection()
    assert (selection.classes, selection.subclasses, selection.eventids) == ([], [], set())
    assert captured_events(selection) == []


def test_unknown_names():
    with pytest.raises(ValueError, match='unknown syscalls: nosuch'):
        parse_live_selection(syscalls=['nosuch'])
    with pytest.raises(ValueError, match='unknown events: nosuch'):
        parse_live_selection(events=['nosuch'])


def test_fs_has_the_guarded_opens():
    # SQLite opens its databases, journals and shared memory with them.
    assert {'BSC_guarded_open_np', 'BSC_guarded_open_dprotected_np'} <= set(
        captured_events(parse_live_selection(groups=['fs'])))


def test_captured_events_of_a_class_are_the_parsed_ones():
    # No XPC event is decoded, so a class prints none, while --xpc selects them by id.
    assert captured_events(parse_live_selection(class_filters=[0x29])) == []
    assert 'XPC_connection_send_message' in captured_events(parse_live_selection(groups=['xpc']))
    assert 'BSC_open' in captured_events(parse_live_selection(bsc=True))

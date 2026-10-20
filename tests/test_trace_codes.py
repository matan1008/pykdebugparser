from pykdebugparser.trace_codes import SYSCALL_GROUPS, default_trace_codes, event_eventids, from_trace_codes_text, \
    group_mach_traps, syscall_eventids, syscall_names

import pytest


@pytest.mark.parametrize('text, out', [
    ('0x40c0548	BSC_stat64', {0x40c0548: 'BSC_stat64'}),
    (('0x80010068 ASPCORE_PUSH_PAGES                                          		'
      '#Params: flow band page size		#Matchby: Arg1'), {0x80010068: 'ASPCORE_PUSH_PAGES'}),
    ('0x40c0548	BSC_stat64\n0x40c054c	BSC_sys_fstat64', {0x40c0548: 'BSC_stat64', 0x40c054c: 'BSC_sys_fstat64'}),
])
def test_from_trace_codes_text(text, out):
    assert from_trace_codes_text(text) == out


def test_syscall_eventids():
    trace_codes = {0x40c0014: 'BSC_open', 0x40c0638: 'BSC_open_nocancel', 0x40c073c: 'BSC_openat',
                   0x40c000c: 'BSC_read'}
    assert syscall_eventids(['open'], trace_codes) == {0x40c0014, 0x40c0638}
    assert syscall_eventids(['openat', 'read'], trace_codes) == {0x40c073c, 0x40c000c}
    assert 0x40c0014 in syscall_eventids(['open'])  # the default trace codes


def test_syscall_eventids_dprotected():
    # Opening with a data protection class is the same call, so it is matched with the plain one.
    trace_codes = {0x40c0014: 'BSC_open', 0x40c0638: 'BSC_open_nocancel', 0x40c0360: 'BSC_open_dprotected_np',
                   0x40c073c: 'BSC_openat', 0x40c0368: 'BSC_openat_dprotected_np'}
    assert syscall_eventids(['open'], trace_codes) == {0x40c0014, 0x40c0638, 0x40c0360}
    assert syscall_eventids(['openat'], trace_codes) == {0x40c073c, 0x40c0368}
    assert syscall_eventids(['open']) >= syscall_eventids(['open_dprotected_np'])  # the default trace codes


def test_syscall_eventids_unknown():
    with pytest.raises(ValueError, match='unknown syscalls: nosuch'):
        syscall_eventids(['open', 'nosuch'], {0x40c0014: 'BSC_open'})


@pytest.mark.parametrize('eventid, name', [
    (0x29000044, 'XPC_connection_send_message'),
    (0x2e030004, 'DISPATCH_MACH_MSG_hdr_move'),
    (0x211200d8, 'CFRL_IS_WAITING'),
    (0x141300bc, 'CFRL_IS_CALLING_SOURCE1'),
])
def test_default_trace_codes_name_userspace_events(eventid, name):
    assert default_trace_codes()[eventid] == name


def test_syscall_names():
    trace_codes = {0x40c0014: 'BSC_open', 0x40c0638: 'BSC_open_nocancel', 0x40c0360: 'BSC_#216',
                   0x40c0640: 'BSC_read_nocancel', 0x1300004: 'MACH_vmfault'}
    # A `_nocancel` variant is left out, unless it is the only one.
    assert syscall_names(trace_codes) == ['open', 'read_nocancel']


def test_event_eventids():
    trace_codes = {0x1f070000: 'DBG_DYLD_A', 0x1f070004: 'DBG_DYLD_A', 0x1f070008: 'DBG_DYLD_B'}
    assert event_eventids(['DBG_DYLD_A'], trace_codes) == {0x1f070000, 0x1f070004}
    with pytest.raises(ValueError, match='unknown events: nosuch'):
        event_eventids(['DBG_DYLD_B', 'nosuch'], trace_codes)


def test_syscall_groups_are_known():
    # Every name of a group is a known syscall or Mach trap.
    syscall_eventids(name for names in SYSCALL_GROUPS.values() for name in names)
    event_eventids(name for group in SYSCALL_GROUPS for name in group_mach_traps(group))
    assert 'MSC_mach_vm_map_trap' in group_mach_traps('mach')
    assert group_mach_traps('fs') == ()

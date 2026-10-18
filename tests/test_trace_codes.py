from pykdebugparser.trace_codes import from_trace_codes_text, syscall_eventids

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


def test_syscall_eventids_unknown():
    with pytest.raises(ValueError, match='unknown syscalls: nosuch'):
        syscall_eventids(['open', 'nosuch'], {0x40c0014: 'BSC_open'})

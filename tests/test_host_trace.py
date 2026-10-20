import errno
import json
import struct
from datetime import timezone

from click.testing import CliRunner
import pytest

from pykdebugparser import __main__ as main
from pykdebugparser import host_trace
from pykdebugparser.host_trace import CTL_KERN, KDBG_TYPENONE, KERN_KDEBUG, KERN_KDENABLE, KERN_KDGETBUF, \
    KERN_KDPIDEX, KERN_KDREADTR, KERN_KDREMOVE, KERN_KDSET_TYPEFILTER, KERN_KDSETBUF, KERN_KDSETUP, KERN_KDTHRMAP, \
    HostTrace, typefilter
from pykdebugparser.pykdebugparser import PyKdebugParser
from pykdebugparser.trace_codes import event_eventids, group_events

THREADMAP = struct.pack('<QI20s', 100, 42, b'probe') + struct.pack('<QI20s', 101, 1, b'launchd')
OP_NAMES = {
    KERN_KDENABLE: 'enable', KERN_KDSETBUF: 'setbuf', KERN_KDGETBUF: 'getbuf', KERN_KDSETUP: 'setup',
    KERN_KDREMOVE: 'remove', KERN_KDREADTR: 'readtr', KERN_KDTHRMAP: 'thrmap', KERN_KDPIDEX: 'pidex',
    KERN_KDSET_TYPEFILTER: 'typefilter',
}


def _kd_buf(timestamp, debugid, values=(0, 0, 0, 0), data=None, tid=100):
    data = struct.pack('<4Q', *values) if data is None else data
    return struct.pack('<Q32sQIIQ', timestamp, data, tid, debugid, 0, 0)


def _open_events():
    lookup = struct.pack('<Q', 0x1234) + b'/usr/libexec/xpcproxy'.ljust(24, b'\x00')
    return [
        _kd_buf(1000, 0x40c0014 | 1, (0x16b000000, 0, 0, 0)),  # open(path, O_RDONLY) start
        _kd_buf(1001, 0x3010090 | 3, data=lookup),  # VFS_LOOKUP (start and end)
        _kd_buf(1002, 0x40c0014 | 2, (0, 3, 0, 0)),  # open end: fd 3
    ]


class FakeKdebug:
    """
    The kdebug sysctl: records the calls, returns the threadmap and the given chunks of events, and stops the trace
    when they run out.
    """

    def __init__(self, chunks=(), threadmap=THREADMAP, fail=None):
        self.chunks = list(chunks)
        self.threadmap = threadmap
        self.fail = fail or {}
        self.calls = []
        self.buffers = {}
        self.trace = None

    def __call__(self, mib, buffer=None):
        assert mib[:2] == [CTL_KERN, KERN_KDEBUG]
        op = mib[2]
        name = OP_NAMES[op]
        self.calls.append((name, *mib[3:]))
        if buffer is not None and op != KERN_KDREADTR:
            self.buffers[name] = bytes(buffer)
        if name in self.fail:
            raise OSError(self.fail[name], 'failed')
        if op == KERN_KDGETBUF:
            struct.pack_into('<iiIii', buffer, 0, 1024, 0, 0x100, len(self.threadmap or b'') // 32, -1)
            return len(buffer)
        if op == KERN_KDTHRMAP:
            if self.threadmap is None:
                raise OSError(errno.ENODATA, 'no threadmap')
            buffer[:len(self.threadmap)] = self.threadmap
            return len(self.threadmap)
        if op == KERN_KDREADTR:
            if not self.chunks:
                self.trace.stop()
                return 0
            chunk = b''.join(self.chunks.pop(0))
            buffer[:len(chunk)] = chunk
            return len(chunk) // 64
        return 0


def _trace(fake, *args, **kwargs):
    kwargs.setdefault('exclude_pid', 1234)
    trace = HostTrace(*args, sysctl=fake, clock=lambda: (1, 1, 0, 0), poll_interval=0, **kwargs)
    fake.trace = trace
    return trace


def _parser(trace):
    parser = PyKdebugParser()
    trace.configure_parser(parser)
    parser.timezone = timezone.utc
    parser.color = False
    return parser


def test_typefilter():
    bitmap = typefilter([4], [0x2b01])
    assert len(bitmap) == 0x2000
    allowed = {csc for csc in range(0x10000) if bitmap[csc >> 3] & (1 << (csc & 7))}
    # DBG_TRACE is always allowed.
    assert allowed == {*range(0x400, 0x500), *range(0x700, 0x800), 0x2b01}


def test_setup_and_teardown_order():
    fake = FakeKdebug()
    with _trace(fake, classes=[4], subclasses=[0x2b01], buffer_events=4096):
        assert fake.calls == [('remove',), ('setbuf', 4096), ('setup',), ('typefilter',), ('pidex',),
                              ('enable', 1), ('getbuf',), ('thrmap',)]
        fake.calls.clear()
    assert fake.calls == [('enable', 0), ('remove',)]
    assert fake.buffers['typefilter'] == typefilter([4], [0x2b01])
    assert fake.buffers['pidex'] == struct.pack('<5I', KDBG_TYPENONE, 1234, 1, 0, 0)


def test_no_filters():
    fake = FakeKdebug()
    with _trace(fake, exclude_pid=None):
        pass
    assert [call[0] for call in fake.calls] == ['remove', 'setbuf', 'setup', 'enable', 'getbuf', 'thrmap', 'enable',
                                                'remove']


def test_teardown_on_setup_failure():
    fake = FakeKdebug(fail={'setup': errno.ENOMEM})
    with pytest.raises(OSError):
        with _trace(fake):
            pass
    assert fake.calls == [('remove',), ('setbuf', host_trace.DEFAULT_BUFFER_EVENTS), ('setup',), ('enable', 0),
                          ('remove',)]


def test_teardown_on_exception():
    fake = FakeKdebug()
    with pytest.raises(ZeroDivisionError):
        with _trace(fake):
            fake.calls.clear()
            1 / 0
    assert fake.calls == [('enable', 0), ('remove',)]


def test_remove_when_disable_fails():
    fake = FakeKdebug()
    trace = _trace(fake)
    trace.start()
    fake.calls.clear()
    fake.fail['enable'] = errno.EPERM
    with pytest.raises(OSError):
        trace.stop()
    assert fake.calls == [('enable', 0), ('remove',)]


def test_traces():
    events = _open_events()
    # The events arrive in chunks that don't line up with the parser's reads.
    fake = FakeKdebug([events[:1], events[1:]])
    with _trace(fake) as trace:
        traces = list(_parser(trace).formatted_traces(trace))
    assert len(traces) == 2
    assert all('probe(42)' in trace for trace in traces)
    assert traces[0].endswith('lookup("/usr/libexec/xpcproxy"), vnode id: 4660')
    assert traces[1].endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3')
    assert trace.events == 3
    assert trace.lost_events == 0


def test_kevents_without_threadmap():
    fake = FakeKdebug([_open_events()], threadmap=None)
    with _trace(fake) as trace:
        events = list(_parser(trace).kevents(trace))
    assert [event.eventid for event in events] == [0x40c0014, 0x3010090, 0x40c0014]


def test_lost_events():
    lost = _kd_buf(999, 0x7020008, (1, 0, 0, 0))  # TRACE_LOST_EVENTS
    # An argument that happens to hold the lost events debugid isn't counted.
    decoy = _kd_buf(1003, 0x40c0014 | 1, (0x7020008, 0, 0, 0))
    fake = FakeKdebug([[lost, *_open_events(), decoy]])
    with _trace(fake) as trace:
        traces = list(_parser(trace).formatted_traces(trace))
    assert trace.lost_events == 1
    assert traces[0].endswith('TRACE_LOST_EVENTS: the kernel dropped trace events here')


def test_time_information():
    fake = FakeKdebug()
    trace = HostTrace(sysctl=fake, clock=lambda: (125, 3, 24000, 1700000000000000), exclude_pid=None)
    fake.trace = trace
    with trace:
        parser = PyKdebugParser()
        trace.configure_parser(parser)
    assert (parser.numer, parser.denom, parser.mach_absolute_time, parser.usecs_since_epoch) == \
        (125, 3, 24000, 1700000000000000)
    assert parser.timezone is not None
    assert parser.live


@pytest.fixture
def cli_fake(monkeypatch):
    fake = FakeKdebug([_open_events()])

    def host_trace_(*args, **kwargs):
        return _trace(fake, *args, **kwargs)

    monkeypatch.setattr(main, 'HostTrace', host_trace_)
    return fake


def test_cli_live(cli_fake):
    result = CliRunner().invoke(main.cli, ['live', '-sf', '0x40c', '--no-color'])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert any(line.endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3') for line in lines)
    assert 'Read 3 events, the kernel dropped events 0 times' in lines
    # The kernel traces VFS_LOOKUP too, it names the paths of syscalls.
    assert cli_fake.buffers['typefilter'] == typefilter([], [0x40c, 0x301])
    assert cli_fake.calls[-2:] == [('enable', 0), ('remove',)]


def test_cli_live_requires_root(cli_fake):
    cli_fake.fail['remove'] = errno.EPERM
    result = CliRunner().invoke(main.cli, ['live'])
    assert result.exit_code == 1
    assert 'requires root' in result.output


def test_skip_behind():
    events = _open_events()
    old = [_kd_buf(1, 0x40c0014 | 1, (0x16b000000, 0, 0, 0)), _kd_buf(2, 0x40c0014 | 2, (0, 4, 0, 0))]
    skips = []
    fake = FakeKdebug([old, events])
    # A tick is a second: the old events are 3s old, the recent ones are 1s old.
    trace = HostTrace(sysctl=fake, clock=lambda: (1000000000, 1, 1003, 0), poll_interval=0, exclude_pid=None,
                      max_lag=2, on_skip=lambda skipped, lag: skips.append((skipped, lag)))
    fake.trace = trace
    with trace:
        traces = list(_parser(trace).formatted_traces(trace))
    assert [trace.split()[-1] for trace in traces] == ['4660', '3']
    assert skips == [(2, 1001.0)]
    assert (trace.events, trace.skipped_events) == (5, 2)


def test_no_skip_without_max_lag():
    fake = FakeKdebug([_open_events()])
    trace = HostTrace(sysctl=fake, clock=lambda: (1000000000, 1, 10 ** 9, 0), poll_interval=0, exclude_pid=None)
    fake.trace = trace
    with trace:
        assert len(list(_parser(trace).formatted_traces(trace))) == 2
    assert trace.skipped_events == 0


def test_on_wait():
    waits = []
    # An empty chunk is a read that found no events.
    fake = FakeKdebug([[], _open_events()])
    trace = HostTrace(sysctl=fake, clock=lambda: (1, 1, 0, 0), poll_interval=0, exclude_pid=None,
                      on_wait=lambda: waits.append(trace.events))
    fake.trace = trace
    with trace:
        assert len(list(_parser(trace).formatted_traces(trace))) == 2
    # Before the events, and once they were all read (when the fake stops the trace).
    assert waits == [0, 3]


def _cli_events():
    # A read the --syscall filter drops.
    read = [_kd_buf(1003, 0x40c000c | 1, (3, 0x1000, 100, 0)), _kd_buf(1004, 0x40c000c | 2, (0, 100, 0, 0))]
    return [*_open_events(), *read]


@pytest.fixture
def parse_live_fake(cli_fake):
    cli_fake.chunks = [_cli_events()]
    return cli_fake


def test_cli_parse_live_bsc(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '--no-color'])
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0].split('|')[-1].strip() == 'Event'
    assert lines[1].endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3')
    assert lines[2].endswith('read(3, 0x1000, 100), count: 100')
    assert 'Read 5 events, the kernel dropped events 0 times, 0 events were skipped to catch up' in lines
    assert parse_live_fake.buffers['typefilter'] == typefilter([], [0x40c, 0x301])
    assert parse_live_fake.calls[-2:] == [('enable', 0), ('remove',)]


@pytest.mark.parametrize('args', [['-s', 'open'], ['--fs']])
def test_cli_parse_live_syscalls(parse_live_fake, args):
    result = CliRunner().invoke(main.cli, ['parse-live', '--no-color', *args])
    assert result.exit_code == 0, result.output
    traces = [line for line in result.output.splitlines()[1:] if not line.startswith('Read ')]
    assert len(traces) == 1
    assert traces[0].endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3')
    # The kernel can only filter the whole subclass.
    assert parse_live_fake.buffers['typefilter'] == typefilter([], [0x40c, 0x301])


def test_cli_parse_live_events(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '-e', 'MSC_mach_vm_map_trap', '--dyld'])
    assert result.exit_code == 0, result.output
    assert parse_live_fake.buffers['typefilter'] == typefilter([0x1f], [0x10c])


def test_cli_parse_live_json(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '-s', 'open', '--json'])
    assert result.exit_code == 0, result.output
    # The output may hold the stats of stderr too, depending on the click version.
    traces = [json.loads(line) for line in result.output.splitlines() if line.startswith('{')]
    assert [(trace['event'], trace['process'], trace['fields']['result']) for trace in traces] == \
        [('BSC_open', 'probe', 'fd: 3')]


def test_cli_parse_live_fast_colors(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '-s', 'open', '--color-mode', 'fast'])
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[1].endswith('\033[32mopen("/usr/libexec/xpcproxy", O_RDONLY), fd: 3\033[0m')


def test_cli_parse_live_unknown_syscall(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '-s', 'nosuch'])
    assert result.exit_code == 2
    assert 'unknown syscalls: nosuch' in result.output
    assert parse_live_fake.calls == []


def test_cli_parse_live_requires_root(parse_live_fake):
    parse_live_fake.fail['remove'] = errno.EPERM
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc'])
    assert result.exit_code == 1
    assert 'requires root' in result.output


def test_cli_events():
    names = CliRunner().invoke(main.cli, ['events']).output.split()
    assert {'DBG_DYLD_TIMING_DLOPEN', 'BSC_open'} <= set(names)


@pytest.mark.parametrize('args, names', [
    (['-s', 'open'], ['BSC_open', 'BSC_open_dprotected_np', 'BSC_open_nocancel']),
    (['--fs', 'guarded'], ['BSC_guarded_open_dprotected_np', 'BSC_guarded_open_np']),
    (['--xpc', 'send_message'], ['XPC_connection_send_message', 'XPC_connection_send_message_with_reply',
                                 'XPC_connection_send_message_with_reply_sync']),
    (['--mem', 'MSC_'], ['MSC_kern_mach_vm_purgable_control_trap', 'MSC_mach_vm_allocate_trap',
                         'MSC_mach_vm_deallocate_trap', 'MSC_mach_vm_map_trap', 'MSC_mach_vm_protect_trap']),
    # A class prints only the events pykdebugparser decodes, the XPC ones are printed when selected by id.
    (['-cf', '0x29'], []),
])
def test_cli_events_with_selection(args, names):
    assert CliRunner().invoke(main.cli, ['events', *args]).output.split() == names


def test_cli_parse_live_event_groups(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '--xpc', '--fs'])
    assert result.exit_code == 0, result.output
    # The kernel traces the subclasses of the XPC events, and every syscall with the lookups that name their paths.
    xpc_subclasses = sorted({eventid >> 16 for eventid in event_eventids(group_events('xpc'))})
    assert parse_live_fake.buffers['typefilter'] == typefilter([], [0x40c, *xpc_subclasses, 0x301])


def test_raise_when_behind_without_skip_behind():
    old = [_kd_buf(1, 0x40c0014 | 1, (0x16b000000, 0, 0, 0))]
    fake = FakeKdebug([_open_events(), old])
    # A tick is a second: the open events are 1s old, the last one 1002s old.
    trace = HostTrace(sysctl=fake, clock=lambda: (1000000000, 1, 1003, 0), poll_interval=0, exclude_pid=None,
                      max_lag=2, skip_behind=False)
    fake.trace = trace
    with pytest.raises(host_trace.TraceLagError) as e:
        with trace:
            list(_parser(trace).formatted_traces(trace))
    assert (e.value.lag, e.value.max_lag) == (1002, 2)
    assert str(e.value) == 'Fell 1002.00s behind, more than the max lag (2s)'
    assert fake.calls[-2:] == [('enable', 0), ('remove',)]


def test_cli_parse_live_lag_error(parse_live_fake, monkeypatch):
    def host_trace_(*args, **kwargs):
        trace = _trace(parse_live_fake, *args, **kwargs)
        trace._clock = lambda: (1000000000, 1, 10 ** 6, 0)
        return trace

    monkeypatch.setattr(main, 'HostTrace', host_trace_)
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '--max-lag', '0.5'])
    assert result.exit_code == 1
    lines = result.output.splitlines()
    assert 'Read 5 events, the kernel dropped events 0 times, 0 events were skipped to catch up' in lines
    assert lines[-1].startswith('Error: Fell ')
    assert lines[-1].endswith('more than the max lag (0.5s). To skip ahead to recent events instead, pass '
                              '--skip-behind (or allow more lag with --max-lag, or narrow the trace)')


def test_cli_parse_live_max_lag_must_be_positive(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '--max-lag', '0'])
    assert result.exit_code == 2
    assert parse_live_fake.calls == []


@pytest.mark.parametrize('args, kept', [
    (['-m', 'xpcproxy'], ['open']),
    (['-m', 'xpcproxy', '-m', 'O_WRONLY'], []),
    (['-mi', 'XPCPROXY'], ['open']),
    (['-v', 'xpcproxy'], ['read']),
    (['-vi', 'PROBE'], []),
    (['-r', r'read\(3', '-r', 'nope'], ['read']),
    (['-ri', 'OPEN.*FD: 3'], ['open']),
])
def test_cli_parse_live_match(parse_live_fake, args, kept):
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '--no-color', *args])
    assert result.exit_code == 0, result.output
    traces = [line.split()[-1] for line in result.output.splitlines()[1:] if not line.startswith('Read ')]
    printed = [name for name in ('open', 'read') if any(name + '(' in line for line in result.output.splitlines())]
    assert printed == kept, traces


def test_cli_parse_live_match_highlights(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '-m', 'xpcproxy'])
    assert result.exit_code == 0, result.output
    assert '\x1b[1;4mxpcproxy\x1b[0m' in result.output
    # The fast color mode highlights too.
    parse_live_fake.chunks = [_cli_events()]
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '-m', 'xpcproxy', '--color-mode', 'fast'])
    assert '\x1b[1;4mxpcproxy\x1b[0m' in result.output


def test_cli_parse_live_match_json(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '--bsc', '--json', '-m', 'probe(42)', '-m', 'read'])
    assert result.exit_code == 0, result.output
    traces = [json.loads(line) for line in result.output.splitlines() if line.startswith('{')]
    assert [trace['event'] for trace in traces] == ['BSC_read']


def test_cli_parse_live_bad_regex(parse_live_fake):
    result = CliRunner().invoke(main.cli, ['parse-live', '-r', '('])
    assert result.exit_code == 2
    assert parse_live_fake.calls == []

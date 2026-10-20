import errno
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

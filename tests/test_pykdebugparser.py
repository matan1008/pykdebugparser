from datetime import datetime, timedelta, timezone
import json
from io import BytesIO
import struct

import pytest

from pykdebugparser.kd_buf_parser import RAW_VERSION2_BYTES, V2_EVENTS_ALIGNMENT
from pykdebugparser.kevent import Kevent
from pykdebugparser.pykdebugparser import PyKdebugParser
from pykdebugparser.trace_codes import default_trace_codes, syscall_eventids
from pykdebugparser import traces_parser
from pykdebugparser.traces_parser import TracesParser

# A trace version 2 header without threads, padded to where its events start.
V2_HEADER = RAW_VERSION2_BYTES + b'\x00' * (V2_EVENTS_ALIGNMENT - len(RAW_VERSION2_BYTES))


def test_kevents():
    events_buf = V2_HEADER
    events_buf += (b'\xa50\x147_\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00y\xd8\t\x00\x00\x00\x00'
                   b'\x00*\x03\x0c\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    parser = PyKdebugParser()
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == [
        Kevent(timestamp=7006015729829,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 454), tid=645241, debugid=67896106, eventid=67896104, func_qualifier=2)
    ]


def test_kevents_filter_tid():
    events_buf = V2_HEADER
    events_buf += (b'\xa50\x147_\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                   b'\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00y\xd8\t\x00\x00\x00\x00'
                   b'\x00*\x03\x0c\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    parser = PyKdebugParser()
    parser.filter_tid = 645241
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == [
        Kevent(timestamp=7006015729829,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\xc6\x01\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 454), tid=645241, debugid=67896106, eventid=67896104, func_qualifier=2)
    ]
    parser.filter_tid = 3
    events = list(parser.kevents(BytesIO(events_buf)))
    assert events == []


class _ChunkedReader:
    """
    A stream whose `read1` returns small pieces, which split kevents between reads.
    """

    def __init__(self, data, piece_size):
        self._stream = BytesIO(data)
        self._piece_size = piece_size

    def read(self, size=-1):
        return self._stream.read(size)

    def read1(self, size=-1):
        return self._stream.read(min(size, self._piece_size))

    def tell(self):
        return self._stream.tell()

    def seek(self, offset, whence=0):
        return self._stream.seek(offset, whence)


class _NoRead1Reader(_ChunkedReader):
    read1 = None


def _kevents_buf(count):
    events_buf = V2_HEADER
    for i in range(count):
        events_buf += (i + 1).to_bytes(8, 'little') + bytes(range(i, i + 32)) + (i * 7).to_bytes(8, 'little')
        events_buf += (0x40c0000 + i).to_bytes(4, 'little') + b'\x00' * 12
    return events_buf


@pytest.mark.parametrize('piece_size', [1, 7, 64, 100, 1000])
def test_kevents_split_reads(piece_size):
    events_buf = _kevents_buf(10)
    expected = list(PyKdebugParser().kevents(BytesIO(events_buf)))
    assert len(expected) == 10
    assert list(PyKdebugParser().kevents(_ChunkedReader(events_buf, piece_size))) == expected
    assert list(PyKdebugParser().kevents(_NoRead1Reader(events_buf, piece_size))) == expected


def test_kevents_truncated_kevent():
    with pytest.raises(struct.error):
        list(PyKdebugParser().kevents(BytesIO(_kevents_buf(2)[:-1])))


@pytest.mark.parametrize('tz', [timezone.utc, timezone(timedelta(hours=3)), timezone(timedelta(hours=-7, minutes=-30))])
@pytest.mark.parametrize('usecs_since_epoch', [1792004006481345.0, 1792004006481345, 1700000000123456.5, 0])
def test_format_timestamp(tz, usecs_since_epoch):
    parser = PyKdebugParser()
    parser.numer, parser.denom, parser.mach_absolute_time = 125, 3, 29547996477653
    parser.usecs_since_epoch, parser.timezone = usecs_since_epoch, tz
    for timestamp in [parser.mach_absolute_time + delta for delta in
                      (0, 1, 12, 24, -12, 23999988, 24000000, -24000000, 10 ** 12 + 12, 3 * 10 ** 13 + 4)]:
        offset_usec = ((timestamp - parser.mach_absolute_time) * parser.numer) / (parser.denom * 1000)
        expected = datetime.fromtimestamp((parser.usecs_since_epoch + offset_usec) / 1000000, tz=tz)
        assert parser._format_timestamp(timestamp) == f"{expected.strftime('%Y-%m-%d %H:%M:%S.%f'):<27}"


def _kd_buf(timestamp, debugid, values=(0, 0, 0, 0), data=None, tid=100):
    data = struct.pack('<4Q', *values) if data is None else data
    return struct.pack('<Q32sQIIQ', timestamp, data, tid, debugid, 0, 0)


def _open_and_read_buf():
    lookup = struct.pack('<Q', 0x1234) + b'/usr/libexec/xpcproxy'.ljust(24, b'\x00')
    events = [
        _kd_buf(1000, 0x40c0014 | 1, (0x16b000000, 0, 0, 0)),  # open(path, O_RDONLY) start
        _kd_buf(1001, 0x3010090 | 3, data=lookup),  # VFS_LOOKUP (start and end)
        _kd_buf(1002, 0x40c0014 | 2, (0, 3, 0, 0)),  # open end: fd 3
        _kd_buf(1003, 0x40c000c | 1, (3, 0x16b000000, 10, 0)),  # read(3, buf, 10) start
        _kd_buf(1004, 0x40c000c | 2, (0, 10, 0, 0)),  # read end: 10 bytes
    ]
    return V2_HEADER + b''.join(events)


def _traces_parser():
    parser = PyKdebugParser()
    parser.color = False
    parser.numer, parser.denom, parser.mach_absolute_time, parser.usecs_since_epoch = 1, 1, 0, 0
    parser.timezone = timezone.utc
    return parser


@pytest.mark.parametrize('filter_class', [[], [0x33]])
def test_kevents_name_processes_created_during_the_trace(filter_class):
    # A thread created by pid 300 forks process 301, which execs: none of them are in the (empty) threadmap.
    events = [
        _kd_buf(1000, 0x7000004, (200, 300, 0, 0), tid=100),  # TRACE_DATA_NEWTHREAD: tid 200 of pid 300
        _kd_buf(1001, 0x7010004, data=b'launchd'.ljust(32, b'\x00'), tid=100),  # TRACE_STRING_NEWTHREAD
        _kd_buf(1002, 0x7000004, (201, 301, 0, 0), tid=200),  # TRACE_DATA_NEWTHREAD: tid 201 of pid 301
        _kd_buf(1003, 0x7010004, data=b'launchd'.ljust(32, b'\x00'), tid=200),  # TRACE_STRING_NEWTHREAD
        _kd_buf(1004, 0x7000008, (301, 0, 0, 0), tid=201),  # TRACE_DATA_EXEC: pid 301
        _kd_buf(1005, 0x7010008, data=b'Preferences'.ljust(32, b'\x00'), tid=201),  # TRACE_STRING_EXEC
        _kd_buf(1006, 0x33010005, (1, 16, 0, 0), tid=201),  # malloc start
        _kd_buf(1007, 0x33010005, (1, 16, 0, 0), tid=200),  # malloc start
    ]
    parser = _traces_parser()
    parser.filter_class = filter_class
    processes = [parser._format_process(event.tid) for event in parser.kevents(BytesIO(V2_HEADER + b''.join(events)))
                 if event.eventid >> 24 == 0x33]
    assert processes == ['Preferences(301)', 'launchd(300)']


def test_traces_filter_eventid():
    parser = _traces_parser()
    parser.filter_eventid = syscall_eventids(['open'])
    traces = list(parser.formatted_traces(BytesIO(_open_and_read_buf())))
    assert len(traces) == 1
    assert traces[0].endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3')


def test_traces_filter_eventid_with_subclass():
    parser = _traces_parser()
    parser.filter_subclass = [0x40c]
    parser.filter_eventid = syscall_eventids(['open'])
    traces = list(parser.formatted_traces(BytesIO(_open_and_read_buf())))
    assert len(traces) == 2
    assert traces[0].endswith('open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3')
    assert traces[1].endswith('read(3, 0x16b000000, 10), count: 10')


def test_traces_filter_eventid_without_handler():
    events = [
        _kd_buf(1000, 0x1400120 | 1),  # MACH_SCHED_THREAD_SELECT start
        _kd_buf(1001, 0x1400120 | 2, (467, 0, 0, 4)),  # MACH_SCHED_THREAD_SELECT end
        _kd_buf(1002, 0x1400140, (0, 3, 0, 0)),  # MACH_PSET_AVG_EXEC_TIME
    ]
    events_buf = V2_HEADER + b''.join(events)
    parser = _traces_parser()
    parser.filter_class = [1]
    assert list(parser.formatted_traces(BytesIO(events_buf))) == []
    parser = _traces_parser()
    parser.filter_eventid = {0x1400120, 0x1400140}
    traces = list(parser.formatted_traces(BytesIO(events_buf)))
    assert len(traces) == 2
    assert traces[0].endswith('MACH_SCHED_THREAD_SELECT(0x0, 0x0, 0x0, 0x0), end: (0x1d3, 0x0, 0x0, 0x4)')
    assert traces[1].endswith('MACH_PSET_AVG_EXEC_TIME(0x0, 0x3, 0x0, 0x0)')


def test_traces_keep_lost_events_when_filtered():
    # The parser adds the TRACE class to filtered traces for its own bookkeeping and hides it again, except for lost
    # events, which tell the reader the trace has a gap.
    events = [
        _kd_buf(1000, 0x7020008, (1, 0, 0, 0)),  # TRACE_LOST_EVENTS
        _kd_buf(1001, 0x1400140, (0, 3, 0, 0)),  # MACH_PSET_AVG_EXEC_TIME
    ]
    events_buf = V2_HEADER + b''.join(events)
    parser = _traces_parser()
    parser.filter_class = [1]
    traces = list(parser.formatted_traces(BytesIO(events_buf)))
    assert len(traces) == 1
    assert traces[0].endswith('TRACE_LOST_EVENTS: the kernel dropped trace events here')


def _two_processes():
    # Thread 200 of launchd (pid 300) and thread 201 of Preferences (pid 301).
    return [
        _kd_buf(900, 0x7000004, (200, 300, 0, 0)),  # TRACE_DATA_NEWTHREAD
        _kd_buf(901, 0x7010004, data=b'launchd'.ljust(32, b'\x00')),  # TRACE_STRING_NEWTHREAD
        _kd_buf(902, 0x7000004, (201, 301, 0, 0)),  # TRACE_DATA_NEWTHREAD
        _kd_buf(903, 0x7010004, data=b'Preferences'.ljust(32, b'\x00')),  # TRACE_STRING_NEWTHREAD
    ]


@pytest.mark.parametrize('process', ['Preferences', '301'])
def test_traces_filter_process_before_parsing(monkeypatch, process):
    events = _two_processes() + [
        _kd_buf(1000, 0x40c000c | 1, (3, 0x16b000000, 10, 0), tid=200),  # read start
        _kd_buf(1001, 0x40c000c | 2, (0, 10, 0, 0), tid=200),  # read end
        _kd_buf(1002, 0x40c000c | 1, (4, 0x16b000000, 10, 0), tid=201),  # read start
        _kd_buf(1003, 0x40c000c | 2, (0, 10, 0, 0), tid=201),  # read end
        _kd_buf(1004, 0x40c000c | 1, (5, 0x16b000000, 10, 0), tid=202),  # read start, of a thread not known yet
        _kd_buf(1005, 0x40c000c | 2, (0, 10, 0, 0), tid=202),  # read end
    ]
    fed_tids = []
    feed = TracesParser.feed
    monkeypatch.setattr(TracesParser, 'feed', lambda self, event: fed_tids.append(event.tid) or feed(self, event))
    parser = _traces_parser()
    parser.filter_process = process
    assert [str(t) for t in parser.traces(BytesIO(V2_HEADER + b''.join(events)))] == \
        ['read(4, 0x16b000000, 10), count: 10']
    # The kevents of a thread known to be of another process aren't parsed, those of a thread not known yet are.
    assert 200 not in fed_tids
    assert 202 in fed_tids


@pytest.mark.parametrize('process, traces', [
    ('launchd', ['P_RdData, dev: 1,2, blkno: 0x10, size: 4096, resid: 0, error: 0']),
    ('Preferences', []),
])
def test_traces_filter_process_disk_io_completed_on_another_thread(process, traces):
    events = _two_processes() + [
        _kd_buf(1000, 0x3020008, (0xb0f, 0x1000002, 0x10, 4096), tid=200),  # P_RdData issue
        _kd_buf(1001, 0x302000c, (0xb0f, 0, 0, 0), tid=201),  # P_RdDataDone, on the thread it interrupted
    ]
    parser = _traces_parser()
    parser.filter_process = process
    # The I/O is of the thread that issued it.
    assert [str(t) for t in parser.traces(BytesIO(V2_HEADER + b''.join(events)))] == traces


def test_traces_filter_process_exec():
    events = _two_processes() + [
        _kd_buf(1000, 0x40c00ec | 1, (0x16b000000, 0, 0, 0), tid=200),  # execve start
        _kd_buf(1001, 0x7000008, (300, 0, 0, 0), tid=200),  # TRACE_DATA_EXEC
        _kd_buf(1002, 0x7010008, data=b'Settings'.ljust(32, b'\x00'), tid=200),  # TRACE_STRING_EXEC
        _kd_buf(1003, 0x40c00ec | 2, (0, 0, 0, 0), tid=200),  # execve end
    ]
    parser = _traces_parser()
    parser.filter_process = 'Settings'
    # The execve began in launchd, and is of the process it made.
    assert [str(t) for t in parser.traces(BytesIO(V2_HEADER + b''.join(events)))] == \
        ['New process name: Settings', 'execve()']


@pytest.mark.parametrize('live, max_ongoing_events, parsed', [(False, 12, True), (True, 13, True), (True, 12, False)])
def test_traces_live_forget_calls_that_keep_too_many_events(monkeypatch, live, max_ongoing_events, parsed):
    monkeypatch.setattr(traces_parser, 'MAX_ONGOING_EVENTS', max_ongoing_events)
    lookup = struct.pack('<Q', 0x1234) + b'/usr/libexec/xpcproxy'.ljust(24, b'\x00')
    events = [
        _kd_buf(1000, 0x40c0014 | 1, (0x16b000000, 0, 0, 0)),  # open(path, O_RDONLY) start
        _kd_buf(1001, 0x3010090 | 3, data=lookup),  # VFS_LOOKUP (start and end)
    ]
    events += [_kd_buf(1002, 0x1400140, (0, 3, 0, 0))] * 10  # MACH_PSET_AVG_EXEC_TIME
    events.append(_kd_buf(1003, 0x40c0014 | 2, (0, 3, 0, 0)))  # open end: fd 3
    parser = _traces_parser()
    parser.live = live
    traces = [t for t in parser.traces(BytesIO(V2_HEADER + b''.join(events))) if t.ktraces[0].timestamp == 1000]
    # A live call that kept as many events as it may (12 before its end) is forgotten.
    assert [str(t) for t in traces] == (['open("/usr/libexec/xpcproxy", O_RDONLY), fd: 3'] if parsed else [])


@pytest.mark.parametrize('live', [False, True])
def test_traces_live_forget_calls_ongoing_across_gaps(live):
    events = [
        _kd_buf(1000, 0x40c000c | 1, (3, 0x16b000000, 10, 0), tid=100),  # read start
        _kd_buf(1001, 0x7020008, (1, 0, 0, 0), tid=300),  # TRACE_LOST_EVENTS
        _kd_buf(1002, 0x40c000c | 1, (4, 0x16b000000, 10, 0), tid=200),  # read start
        _kd_buf(1003, 0x7020008, (1, 0, 0, 0), tid=300),  # TRACE_LOST_EVENTS
        _kd_buf(1004, 0x40c000c | 2, (0, 10, 0, 0), tid=100),  # read end
        _kd_buf(1005, 0x40c000c | 2, (0, 10, 0, 0), tid=200),  # read end
    ]
    parser = _traces_parser()
    parser.live = live
    traces = [str(t) for t in parser.traces(BytesIO(V2_HEADER + b''.join(events)))]
    # A live call ongoing since before the previous gap most likely lost its end.
    assert traces == ['TRACE_LOST_EVENTS: the kernel dropped trace events here'] * 2 + \
        ['read(3, 0x16b000000, 10), count: 10'] * (not live) + ['read(4, 0x16b000000, 10), count: 10']


@pytest.mark.parametrize('live', [False, True])
def test_traces_live_forget_the_strings_and_images_of_exited_processes(live):
    initializer = [
        _kd_buf(1003, 0x1f070000 | 1, (0, 0x1000, 0x1234, 0)),  # DBG_DYLD_TIMING_STATIC_INITIALIZER start, mh 0x1000
        _kd_buf(1004, 0x1f070000 | 2),  # DBG_DYLD_TIMING_STATIC_INITIALIZER end
    ]
    events = [
        _kd_buf(1000, 0x7010000 | 3, data=struct.pack('<QQ', 0, 0x10) + b'/usr/lib/libz'.ljust(16, b'\x00')),  # string 0x10
        _kd_buf(1001, 0x1f050000, data=b'\x11' * 16 + struct.pack('<QQ', 0x1000, 0)),  # DYLD_uuid_map_a: at 0x1000
        _kd_buf(1002, 0x1f050004, (0, 0x10, 0, 0)),  # DYLD_uuid_map_b: path string 0x10
        *initializer,
        _kd_buf(1005, 0x701000c, data=b'ls'.ljust(32, b'\x00')),  # TRACE_STRING_PROC_EXIT
        *initializer,
    ]
    parser = TracesParser(default_trace_codes(), {100: 42}, {}, live)
    traces = list(parser.feed_generator(PyKdebugParser().kevents(BytesIO(V2_HEADER + b''.join(events)))))
    initializers = [trace.image for trace in traces if type(trace).__name__ == 'DyldStaticInitializer']
    # A live trace forgets them once the process exits (or execs).
    assert initializers == ['/usr/lib/libz', '' if live else '/usr/lib/libz']
    assert bool(parser.global_strings) != live


@pytest.mark.parametrize('live', [False, True])
def test_traces_live_forget_released_strings(monkeypatch, live):
    monkeypatch.setattr(traces_parser, 'MAX_RELEASED_STRINGS', 1)
    events = []
    for str_id in (0x10, 0x11):
        name = struct.pack('<QQ', 0, str_id) + b'name'.ljust(16, b'\x00')
        events.append(_kd_buf(1000, 0x7010000 | 3, data=name))  # TRACE_STRING_GLOBAL
    for str_id in (0x10, 0x11):
        events.append(_kd_buf(1001, 0x7010000 | 3, (0, str_id, 0, 0)))  # TRACE_STRING_GLOBAL without a string: release
    parser = TracesParser(default_trace_codes(), {100: 42}, {}, live)
    list(parser.feed_generator(PyKdebugParser().kevents(BytesIO(V2_HEADER + b''.join(events)))))
    # Events may still name a released string for a short while, a live trace keeps the last ones released.
    assert set(parser.global_strings) == ({0x11} if live else {0x10, 0x11})


@pytest.mark.parametrize('live', [False, True])
def test_traces_forget_the_calls_of_terminated_threads(live):
    events = [
        _kd_buf(1000, 0x40c0014 | 1, (0x16b000000, 0, 0, 0), tid=200),  # open start, never ends
        _kd_buf(1001, 0x1400140, (0, 3, 0, 0), tid=200),  # MACH_PSET_AVG_EXEC_TIME
        _kd_buf(1002, 0x700000c, (200, 0, 0, 0), tid=100),  # TRACE_DATA_THREAD_TERMINATE: tid 200
    ]
    parser = TracesParser(default_trace_codes(), {200: 42}, {}, live)
    traces = list(parser.feed_generator(PyKdebugParser().kevents(BytesIO(V2_HEADER + b''.join(events)))))
    assert str(traces[-1]) == 'Thread terminated tid: 200, pid: 42'
    assert 200 not in parser.on_going_events
    # A live trace forgets the thread too.
    assert (200 in parser.threads_pids) != live


def test_traces_dyld_strings_traced_before_the_trace():
    # A live trace starts after dyld named some of its strings (a TRACE_STRING_GLOBAL each).
    events = [
        _kd_buf(1000, 0x1f080000 | 1, (0, 0x1234, 1, 0)),  # DBG_DYLD_TIMING_DLOPEN start, path string 0x1234
        _kd_buf(1001, 0x1f080000 | 2, (0, 0x5678, 0, 0)),  # DBG_DYLD_TIMING_DLOPEN end
        _kd_buf(1002, 0x1f08000c | 1, (0, 0x5678, 0x4321, 0)),  # DBG_DYLD_TIMING_DLSYM start, symbol string 0x4321
        _kd_buf(1003, 0x1f08000c | 2, (0, 0x9000, 0, 0)),  # DBG_DYLD_TIMING_DLSYM end
    ]
    parser = _traces_parser()
    traces = list(parser.traces(BytesIO(V2_HEADER + b''.join(events))))
    assert [type(trace).__name__ for trace in traces] == ['Dlopen', 'Dlsym']
    assert (traces[0].path, traces[1].symbol) == ('', '')


def test_dict_traces():
    events = [
        _kd_buf(1000, 0x40c0014 | 1, (0x16d2c2b80, 0, 0, 0)),  # open start
        _kd_buf(2000, 0x40c0014 | 2, (2, 0, 0, 0)),  # open end: ENOENT
    ]
    events_buf = V2_HEADER + b''.join(events)
    parser = _traces_parser()
    (unknown_process,) = parser.dict_traces(BytesIO(events_buf))
    assert (unknown_process['pid'], unknown_process['process']) == (None, '')
    # The thread's process, once the trace has seen it.
    (parsed,) = parser.traces(BytesIO(events_buf))
    parser.threads_pids[100] = 42
    parser.pids_names[42] = 'probe'
    trace = parser.trace_dict(parsed)
    assert trace == {
        'timestamp': 1000,
        'time': '1970-01-01T00:00:00.000001+00:00',
        'tid': 100,
        'pid': 42,
        'process': 'probe',
        'event': 'BSC_open',
        'fields': trace['fields'],
        'text': trace['text'],
    }
    assert trace['text'].startswith('open(') and trace['text'].endswith('errno: ENOENT(2)')
    assert json.loads(json.dumps(trace)) == trace  # JSON-compatible: enums by name, flags as lists of names


def test_trace_dict_values():
    from enum import Enum
    from dataclasses import dataclass
    from uuid import UUID
    from pykdebugparser.trace_handlers import UnknownEnumValue

    class Color(Enum):
        RED = 1

    @dataclass
    class Inner:
        ktraces: list
        value: int

    @dataclass
    class Trace:
        ktraces: list
        color: Color
        unknown: UnknownEnumValue
        flags: list
        uuid: UUID
        data: bytes
        inner: Inner

    event = Kevent(timestamp=5, data=b'\x00' * 32, values=(0, 0, 0, 0), tid=7, debugid=0x40c0015, eventid=0x40c0014,
                   func_qualifier=1)
    trace = Trace([event], Color.RED, UnknownEnumValue(9), [Color.RED], UUID(int=1), b'\x01\x02', Inner([event], 3))
    parser = PyKdebugParser()
    assert parser.trace_dict(trace)['fields'] == {
        'color': 'RED', 'unknown': 9, 'flags': ['RED'], 'uuid': '00000000-0000-0000-0000-000000000001',
        'data': '0102', 'inner': {'value': 3},
    }
    # Without the device's time information there is no wall-clock time.
    assert parser.trace_dict(trace)['time'] is None

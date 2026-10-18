from io import BytesIO
import plistlib
import struct

import pytest

from pykdebugparser.kd_buf_parser import KdBufParser, KdHeaderV2, KdHeaderV3, RAW_VERSION2_BYTES, RAW_VERSION3_BYTES
from pykdebugparser.os_log_event import OsLogEvent

THREADMAP = [(0x1001, 100, b'launchd'), (0x1002, 200, b'SpringBoard'), (0x1003, 200, b'x' * 19)]
CPU_INFO = {'cpus': [{'type': 12}], 'name': 'iPhone'}


def kd_buf(timestamp, tid, debugid=0x40c0029):
    return struct.pack('<Q32sQIIQ', timestamp, bytes(range(32)), tid, debugid, 0, 0)


def threadmap_bytes():
    return b''.join(struct.pack('<QI20s', tid, pid, name) for tid, pid, name in THREADMAP)


def v2_header(flags=1):
    # kperf leaves the unused tail of the header uninitialized.
    return struct.pack('<IQIIQ', len(THREADMAP), 0, 0, flags, 24000000) + bytes(range(0x100))


def v2_buf(padding, events):
    header = RAW_VERSION2_BYTES + v2_header() + threadmap_bytes()
    return header + b'\x00' * padding + b''.join(events)


class _NoRead1Reader:
    """
    A stream without `read1` whose `seek` requires `whence`, like a live kdebug stream.
    """

    def __init__(self, data):
        self._stream = BytesIO(data)

    def read(self, size=-1):
        return self._stream.read(size)

    def tell(self):
        return self._stream.tell()

    def seek(self, offset, whence):
        return self._stream.seek(offset, whence)


@pytest.mark.parametrize('reader_type', [BytesIO, _NoRead1Reader])
@pytest.mark.parametrize('padding', [0, 1, 7, 4096 - 0x120 - 4 - len(THREADMAP) * 32])
def test_parse_v2_threadmap(reader_type, padding):
    parser = KdBufParser()
    events = list(parser.parse(reader_type(v2_buf(padding, [kd_buf(0x101, 0x1001), kd_buf(0x202, 0x1002)]))))
    assert [(e.timestamp, e.tid) for e in events] == [(0x101, 0x1001), (0x202, 0x1002)]
    assert parser.threads_pids == {0x1001: 100, 0x1002: 200, 0x1003: 200}
    assert parser.pids_names == {100: 'launchd', 200: 'x' * 19}


@pytest.mark.parametrize('flags, is_64bit', [(0, False), (1, True)])
def test_kd_header_v2(flags, is_64bit):
    header = KdHeaderV2.parse(v2_header(flags))
    assert header == KdHeaderV2(number_of_threads=len(THREADMAP), tod_secs=0, tod_usecs=0, flags=flags,
                                tick_frequency=24000000)
    assert header.is_64bit is is_64bit


def test_parse_v2_truncated_threadmap():
    with pytest.raises(ValueError):
        list(KdBufParser().parse(BytesIO(v2_buf(0, [])[:-1])))


def block(tag, data, aligned=True):
    out = tag + struct.pack('<Q', len(data)) + data
    return out + (b'\x00' * (-len(out) % 8) if aligned else b'')


def v3_buf():
    cpu_info = plistlib.dumps(CPU_INFO, fmt=plistlib.FMT_BINARY)
    header = struct.pack('<IIQIIQQIIIII', 0x1000, 3, 0x40, 125, 3, 0x1234, 1700000000, 123456, 60, 1, 1, 0x1001)
    header += struct.pack('<Q', len(cpu_info)) + cpu_info
    header += b'\x00' * (-len(header) % 8)
    data = RAW_VERSION3_BYTES + header + b'\x00' * 4
    data += b'\x01' * 10 + b'stackshot_out_fl' + b'\x02' * 3
    data += b'\x00\x1d\x00\x00\x00\x00\x00\x00' + struct.pack('<Q', len(THREADMAP) * 32) + threadmap_bytes()
    events = kd_buf(1, 0x1001) + kd_buf(2, 0x1002)
    data += b'\x00\x1e\x00\x00\x00\x00\x00\x00' + struct.pack('<Q', len(events)) + b'\x00' * 8 + events
    data += b'\x00\x20\x00\x00\x00\x00\x00\x00'
    data += b'\x00\x1e\x00\x00\x00\x00\x00\x00' + struct.pack('<Q', 64) + b'\x00' * 8 + kd_buf(3, 0x1003)
    log_event = {'cm': 0, 't': 'logEvent', 's': 1, 'tid': 0x2001, 'ns': 0, 'mct': 0, 'b': b'', 'piu': b'',
                 'ud': {'sec': 0, 'usec': 0}, 'utz': {'mw': 0, 'dt': 0}, 'p': 1, 'pid': 300,
                 'ti': 0x0000002a_00020104}
    data += block(b'\x0f\x80\x00\x00\x00\x00\x00\x00', b'0x1234567\tFOO_bar\n')
    data += block(b'\x01\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'Binaries': [1]}))
    data += block(b'\x01\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'Binaries': [2]}))
    data += block(b'\x10\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'Processes': [3]}))
    data += block(b'\x05\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'Binaries': [4]}))
    data += block(b'\x04\x80\x00\x00\x01\x00\x00\x00', plistlib.dumps({'Images': [5]}))
    data += block(b'\x12\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'StringIndex': {'hello': 0, 'logd': 1}}))
    # The last block isn't padded.
    data += block(b'\x11\x80\x00\x00\x00\x00\x00\x00', plistlib.dumps({'Events': [log_event]}), aligned=False)
    return data


def test_parse_v3():
    parser = KdBufParser()
    events = list(parser.parse(BytesIO(v3_buf())))
    assert [(e.timestamp, e.tid) for e in events[:3]] == [(1, 0x1001), (2, 0x1002), (3, 0x1003)]
    assert parser.v3_header == KdHeaderV3(0x1000, 3, 0x40, 125, 3, 0x1234, 1700000000, 123456, 60, 1, 1, 0x1001,
                                          CPU_INFO)
    assert parser.v3_header.cpu_info == CPU_INFO
    assert parser.trace_codes == '0x1234567\tFOO_bar\n'
    assert parser.dyld_modules == {'Binaries': [1, 2]}
    assert parser.processes == {'Processes': [3]}
    assert parser.kernel_extensions == {'Binaries': [4]}
    assert parser.images == {'Images': [5]}
    log_event = events[3]
    assert isinstance(log_event, OsLogEvent)
    assert (log_event.composed_message, log_event.process, log_event.trace_identifier.code) == ('hello', 'logd', 42)
    assert parser.threads_pids == {0x1001: 100, 0x1002: 200, 0x1003: 200, 0x2001: 300}
    assert parser.pids_names == {100: 'launchd', 200: 'x' * 19, 300: 'logd'}

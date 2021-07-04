import struct
from collections import namedtuple
import io
import plistlib

from construct import Adapter, Struct, Const, Padding, Int32ul, Int64ul, Array, GreedyRange, Byte, FixedSized, \
    CString, Prefixed, GreedyBytes, Aligned

from pykdebugparser.kevent import from_kd_buf, KD_BUF_FORMAT

KEVENT_SIZE = struct.calcsize(KD_BUF_FORMAT)

ProcessData = namedtuple('ProcessData', ['pid', 'name'])

RAW_VERSION_SIZE = 4
RAW_VERSION2_BYTES = b'\x00\x02\xaa\x55'
RAW_VERSION3_BYTES = b'\x00\x03\xaa\x55'
TRACEV3_STACKSHOT_END = b'stackshot_out_fl'
TRACEV3_THREADMAP_TAG = b'\x00\x1d\x00\x00\x00\x00\x00\x00'
TRACEV3_EVENTS_TAG = b'\x00\x1e\x00\x00\x00\x00\x00\x00'
TRACEV3_MORE_EVENTS = b'\x00\x20\x00\x00\x00\x00\x00\x00'

kd_threadmap = Struct(
    'tid' / Int64ul,
    'pid' / Int32ul,
    'process' / FixedSized(0x14, CString('utf8')),
)


class BplistAdapter(Adapter):
    """
    Construct adapter ti build and parse plists.
    """

    def _decode(self, obj, context, path):
        return plistlib.loads(obj)

    def _encode(self, obj, context, path):
        return plistlib.dumps(obj)


kd_header_v2 = Struct(
    'number_of_treads' / Int32ul,
    Padding(8),
    Padding(4),
    'is_64bit' / Int32ul,
    'tick_frequency' / Int64ul,
    Padding(0x100),
    'threadmap' / Array(lambda ctx: ctx.number_of_treads, kd_threadmap),
    '_pad' / GreedyRange(Const(0, Byte)),
)

kd_header_v3 = Struct(
    'tag' / Int32ul,
    'sub_tag' / Int32ul,
    'length' / Int64ul,
    'timebase_numer' / Int32ul,
    'timebase_denom' / Int32ul,
    'timestamp' / Int64ul,
    'walltime_secs' / Int64ul,
    'walltime_usecs' / Int32ul,
    'timezone_minuteswest' / Int32ul,
    'timezone_dst' / Int32ul,
    'flags' / Int32ul,
    'tag2' / Int32ul,
    'cpu_info' / Prefixed(Int64ul, BplistAdapter(GreedyBytes)),

)

kd_v3_threadmap = Struct(
    'threadmap' / Prefixed(Int64ul, GreedyRange(kd_threadmap)),
)


def seek_until(reader, data: bytes):
    """
    Read from a stream until matching data.
    Reading is aligned to the data size.
    :param reader: Stream to read from.
    :param data: Data to match.
    """
    while True:
        if reader.read(len(data)) == data:
            break


class KdBufParser:
    """
    Parser for raw kd_buf buffer.
    """

    def __init__(self, thread_map=None):
        self._thread_map = {} if thread_map is None else thread_map
        self.versions = {
            RAW_VERSION2_BYTES: self.parse_v2,
            RAW_VERSION3_BYTES: self.parse_v3,
        }
        self.trace_codes = ''
        self.binaries = {}
        self.images = {}
        self.kernel_binaries = {}
        self.v3_header = None

    def parse(self, reader: io.IOBase):
        """
        Parse kevents from a stream.
        :param reader: Stream to read from.
        :return: Generator for parsed kevents.
        """
        version = reader.read(RAW_VERSION_SIZE)
        return self.versions[version](reader)

    @property
    def thread_map(self):
        """
        Mapping between thread id to its process id and process name.
        """
        return self._thread_map

    @thread_map.setter
    def thread_map(self, parsed_threadmap):
        self._thread_map.clear()
        for thread in parsed_threadmap:
            self._thread_map[thread.tid] = ProcessData(thread.pid, thread.process)

    def parse_v2(self, reader: io.IOBase):
        """
        Parse trace version 2.
        :param reader: Stream to parse.
        :return: Generator for parsed kevents.
        """
        parsed_header = kd_header_v2.parse_stream(reader)
        self.thread_map = parsed_header.threadmap
        while True:
            buf = reader.read(KEVENT_SIZE)
            if not buf:
                break
            yield from_kd_buf(buf)

    def parse_v3(self, reader: io.IOBase):
        """
        Parse trace version 3.
        :param reader: Stream to parse.
        :return: Generator for parsed kevents.
        """
        self.v3_header = Aligned(8, kd_header_v3).parse_stream(reader)
        # Align the reader to 8 bytes from the beginning of the stream
        reader.read(8 - RAW_VERSION_SIZE)
        # The threadmap tag appears randomly in the stackshot.
        seek_until(reader, TRACEV3_STACKSHOT_END)
        seek_until(reader, TRACEV3_THREADMAP_TAG)
        threadmap = kd_v3_threadmap.parse_stream(reader).threadmap
        self.thread_map = threadmap

        while True:
            seek_until(reader, TRACEV3_EVENTS_TAG)
            size = Int64ul.parse_stream(reader)
            reader.read(8)  # All zeros, unknown.
            for _ in range(size // KEVENT_SIZE):
                buf = reader.read(KEVENT_SIZE)
                yield from_kd_buf(buf)
            if reader.read(len(TRACEV3_MORE_EVENTS)) != TRACEV3_MORE_EVENTS:
                break

        size = Int64ul.parse_stream(reader)
        self.trace_codes = reader.read(size).decode()
        reader.read(10)  # Unknown.
        size = Int64ul.parse_stream(reader)
        self.trace_codes += reader.read(size).decode()
        reader.read(10)  # Unknown.
        size = Int64ul.parse_stream(reader)
        self.binaries.update(plistlib.loads(reader.read(size)))
        reader.read(12)  # Unknown.
        size = Int64ul.parse_stream(reader)
        self.images.update(plistlib.loads(reader.read(size)))
        reader.read(12)  # Unknown.
        size = Int64ul.parse_stream(reader)
        self.kernel_binaries.update(plistlib.loads(reader.read(size)))

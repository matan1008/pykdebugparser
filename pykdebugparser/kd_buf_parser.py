from dataclasses import dataclass, field
import io
import plistlib
import struct
from collections import namedtuple
from typing import Annotated, Any

from bytestruct import GREEDY_BYTES, U64_LE, BinaryParseError, BinaryStruct, ByteReader, Bytes, CodecBase, \
    PaddedString, Prefixed, TruncatedDataError, u32, u64

from pykdebugparser.kevent import from_kd_buf, from_kd_bufs, KD_BUF_FORMAT
from pykdebugparser.os_log_event import OsLogEvent

KEVENT_SIZE = struct.calcsize(KD_BUF_FORMAT)
# Upper bound for a single bulk read of kevents.
KEVENTS_READ_SIZE = KEVENT_SIZE * 1024

ProcessData = namedtuple('ProcessData', ['pid', 'name'])

RAW_VERSION_SIZE = 4
RAW_VERSION2_BYTES = b'\x00\x02\xaa\x55'
RAW_VERSION3_BYTES = b'\x00\x03\xaa\x55'
# The events of a trace version 2 start at this alignment from the beginning of the trace.
V2_EVENTS_ALIGNMENT = 0x1000
# Header flag of a 64-bit kernel.
KDBG_LP64 = 0x1
TRACEV3_STACKSHOT_END = b'stackshot_out_fl'
TRACEV3_THREADMAP_TAG = b'\x00\x1d\x00\x00\x00\x00\x00\x00'
TRACEV3_EVENTS_TAG = b'\x00\x1e\x00\x00\x00\x00\x00\x00'
TRACEV3_MORE_EVENTS = b'\x00\x20\x00\x00\x00\x00\x00\x00'
TRACEV3_DYLD_MODULES = b'\x01\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_TRACE_CODES = b'\x0f\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_PROCESSES = b'\x10\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_LOG_EVENTS = b'\x11\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_LOG_STRINGS = b'\x12\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_KERNEL_EXTENSIONS = b'\x05\x80\x00\x00\x00\x00\x00\x00'
TRACEV3_IMAGES = b'\x04\x80\x00\x00\x01\x00\x00\x00'


class Bplist(CodecBase[Any]):
    """
    Codec for a plist (all remaining bytes).
    """

    def read(self, reader: ByteReader) -> Any:
        return plistlib.loads(GREEDY_BYTES.read(reader))

    def build(self, value: Any) -> bytes:
        return plistlib.dumps(value)


@dataclass
class KdThreadmap(BinaryStruct, byte_order='<'):
    tid: u64
    pid: u32
    process: Annotated[str, PaddedString(0x14)]


@dataclass
class KdHeaderV2(BinaryStruct, byte_order='<'):
    """
    Header of a trace version 2 (`RAW_VERSION2`), as written by kperf's `kperf_buffer_readdata`.
    The fields up to `tod_usecs` follow XNU's `RAW_header`; kperf always writes the time of day as zero.
    """
    number_of_threads: u32
    tod_secs: u64
    tod_usecs: u32
    flags: u32
    tick_frequency: u64
    # Never written by kperf, so it holds whatever the buffer contained before.
    _unused: Annotated[bytes, Bytes(0x100)] = field(default=bytes(0x100), init=False, repr=False, compare=False)

    @property
    def is_64bit(self) -> bool:
        return bool(self.flags & KDBG_LP64)


@dataclass
class KdHeaderV3(BinaryStruct, byte_order='<'):
    tag: u32
    sub_tag: u32
    length: u64
    timebase_numer: u32
    timebase_denom: u32
    timestamp: u64
    walltime_secs: u64
    walltime_usecs: u32
    timezone_minuteswest: u32
    timezone_dst: u32
    flags: u32
    tag2: u32
    cpu_info: Annotated[Any, Prefixed(U64_LE, Bplist())]


@dataclass
class KdV3Block(BinaryStruct, byte_order='<'):
    """
    An additional data block of a trace version 3, aligned to 8 bytes (unless it is the last one).
    """
    tag: Annotated[bytes, Bytes(8)]
    data: Annotated[bytes, Prefixed(U64_LE, GREEDY_BYTES)]


def read_exactly(reader: io.IOBase, size: int) -> bytes:
    """
    Read exactly `size` bytes from a stream.
    :param reader: Stream to read from.
    :param size: Number of bytes to read.
    :return: The data read.
    :raises TruncatedDataError: The stream ended first.
    """
    data = reader.read(size)
    if len(data) != size:
        raise TruncatedDataError(f'expected {size} bytes, found {len(data)}')
    return data


def parse_threadmap(data: bytes) -> list:
    """
    Parse consecutive threadmap entries, stopping at the first one that can't be parsed.
    :param data: Threadmap entries.
    :return: Parsed entries.
    """
    reader = ByteReader(data)
    threadmap = []
    while reader.remaining:
        try:
            threadmap.append(KdThreadmap.read(reader))
        except BinaryParseError:
            break
    return threadmap


def parse_v3_blocks(data: bytes) -> list:
    """
    Parse the additional data blocks of a trace version 3, stopping at the first one that can't be parsed.
    :param data: Additional data blocks.
    :return: Parsed blocks.
    """
    reader = ByteReader(data)
    blocks = []
    while True:
        try:
            block = KdV3Block.read(reader)
        except BinaryParseError:
            break
        blocks.append(block)
        # The last block may be unpadded.
        reader.skip(min(-(KdV3Block.SIZE + 8 + len(block.data)) % 8, reader.remaining))
    return blocks


def seek_until(reader, data: bytes):
    """
    Read from a stream until matching data.
    Reading is aligned to the data size.
    :param reader: Stream to read from.
    :param data: Data to match.
    """
    found = reader.read(len(data))
    while found != data:
        found = found[1:] + reader.read(1)


class KdBufParser:
    """
    Parser for raw kd_buf buffer.
    """

    def __init__(self, threads_pids=None, pids_names=None):
        self.threads_pids = {} if threads_pids is None else threads_pids
        self.pids_names = {} if pids_names is None else pids_names
        self.versions = {
            RAW_VERSION2_BYTES: self.parse_v2,
            RAW_VERSION3_BYTES: self.parse_v3,
        }
        self.trace_codes = ''
        self.images = {}
        self.dyld_modules = {}
        self.processes = {}
        self.kernel_extensions = {'Binaries': []}
        self.v3_header = None

    def parse(self, reader: io.IOBase):
        """
        Parse kevents from a stream.
        :param reader: Stream to read from.
        :return: Generator for parsed kevents.
        """
        version = reader.read(RAW_VERSION_SIZE)
        return self.versions[version](reader)

    def set_thread_map(self, parsed_threadmap):
        self.threads_pids.clear()
        self.pids_names.clear()
        for thread in parsed_threadmap:
            # xnu marks the threadmap's entries valid with their pid, and those of kernel_task (pid 0) with 1, the pid
            # of launchd (`_resolve_kernel_task` in bsd/kern/kdebug.c).
            pid = 0 if thread.pid == 1 and thread.process == 'kernel_task' else thread.pid
            self.threads_pids[thread.tid] = pid
            self.pids_names[pid] = thread.process

    def parse_v2(self, reader: io.IOBase):
        """
        Parse trace version 2.
        :param reader: Stream to parse.
        :return: Generator for parsed kevents.
        """
        header = KdHeaderV2.parse(read_exactly(reader, KdHeaderV2.SIZE))
        self.set_thread_map([KdThreadmap.parse(read_exactly(reader, KdThreadmap.SIZE))
                             for _ in range(header.number_of_threads)])
        # The header and threadmap are padded to a 4 KiB boundary, and the padding is left uninitialized (it often
        # holds stale data, such as trace codes text), so the events start at that boundary rather than at the first
        # non-zero byte.
        reader.read(-(RAW_VERSION_SIZE + KdHeaderV2.SIZE + header.number_of_threads * KdThreadmap.SIZE)
                    % V2_EVENTS_ALIGNMENT)
        read1 = getattr(reader, 'read1', None)
        if read1 is None:
            # Without `read1` a bigger `read` might block until more data than currently available arrives.
            while True:
                buf = reader.read(KEVENT_SIZE)
                if not buf:
                    break
                yield from_kd_buf(buf)
            return
        # `read1` returns whatever is available, so kevents are decoded in bulk without delaying live streams.
        leftover = b''
        while True:
            buf = read1(KEVENTS_READ_SIZE)
            if not buf:
                break
            if leftover:
                buf = leftover + buf
            end = len(buf) - len(buf) % KEVENT_SIZE
            if end != len(buf):
                leftover = buf[end:]
                buf = buf[:end]
            else:
                leftover = b''
            yield from from_kd_bufs(buf)
        if leftover:
            # A truncated kevent, fail just like a non-bulk read would.
            yield from_kd_buf(leftover)

    def parse_v3(self, reader: io.IOBase):
        """
        Parse trace version 3.
        :param reader: Stream to parse.
        :return: Generator for parsed kevents.
        """
        header = read_exactly(reader, KdHeaderV3.SIZE + U64_LE.size)
        header += read_exactly(reader, U64_LE.unpack_from(header, KdHeaderV3.SIZE)[0])
        read_exactly(reader, -len(header) % 8)
        self.v3_header = KdHeaderV3.parse(header)
        # Align the reader to 8 bytes from the beginning of the stream
        reader.read(8 - RAW_VERSION_SIZE)
        # The threadmap tag appears randomly in the stackshot.
        seek_until(reader, TRACEV3_STACKSHOT_END)
        seek_until(reader, TRACEV3_THREADMAP_TAG)
        threadmap_size = U64_LE.parse(read_exactly(reader, U64_LE.size))
        self.set_thread_map(parse_threadmap(read_exactly(reader, threadmap_size)))

        while True:
            seek_until(reader, TRACEV3_EVENTS_TAG)
            size = U64_LE.parse(read_exactly(reader, U64_LE.size))
            reader.read(8)  # All zeros, unknown.
            for _ in range(size // KEVENT_SIZE):
                buf = reader.read(KEVENT_SIZE)
                yield from_kd_buf(buf)
            if reader.read(len(TRACEV3_MORE_EVENTS)) != TRACEV3_MORE_EVENTS:
                break
        reader.seek(-8, 1)

        additional_data = parse_v3_blocks(reader.read())

        self.trace_codes = ''
        self.kernel_extensions = {'Binaries': []}
        self.dyld_modules = {}
        self.images = {}
        self.processes = {}

        log_events = []
        log_strings = {}

        for block in additional_data:
            if block.tag == TRACEV3_DYLD_MODULES:
                data = plistlib.loads(block.data)
                if not self.dyld_modules:
                    self.dyld_modules.update(data)
                else:
                    self.dyld_modules['Binaries'].extend(data['Binaries'])
            elif block.tag == TRACEV3_TRACE_CODES:
                self.trace_codes += block.data.decode()
            elif block.tag == TRACEV3_PROCESSES:
                self.processes = plistlib.loads(block.data)
            elif block.tag == TRACEV3_KERNEL_EXTENSIONS:
                self.kernel_extensions['Binaries'].extend(plistlib.loads(block.data)['Binaries'])
            elif block.tag == TRACEV3_IMAGES:
                self.images = plistlib.loads(block.data)
            elif block.tag == TRACEV3_LOG_EVENTS:
                log_events.extend(plistlib.loads(block.data)['Events'])
            elif block.tag == TRACEV3_LOG_STRINGS:
                log_strings = {v: k for k, v in plistlib.loads(block.data)['StringIndex'].items()}

        for event in log_events:
            log_event = OsLogEvent.from_raw_log_event(event, log_strings)
            if log_event.process and log_event.thread_identifier:
                self.threads_pids[log_event.thread_identifier] = log_event.process_identifier
                self.pids_names[log_event.process_identifier] = log_event.process
            yield log_event

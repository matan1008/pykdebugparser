"""
Live kdebug tracing of the macOS host.

The kernel trace facility is driven through the `kern.kdebug` sysctl (`CTL_KERN`, `KERN_KDEBUG`), which only
requires root. Events are read with `KERN_KDREADTR` as raw `kd_buf` records, and presented as a version 2 trace
(header, threadmap from `KERN_KDTHRMAP` and the records), so `PyKdebugParser` decodes them like any trace file.

The trace facility is global to the system, `HostTrace` always disables and removes it when it stops.
"""
import ctypes
import ctypes.util
import errno
import os
import struct
import sys
import time
from datetime import datetime
from typing import Callable, Iterable, Optional

from pykdebugparser.kd_buf_parser import KDBG_LP64, RAW_VERSION2_BYTES, KdHeaderV2, KdThreadmap
from pykdebugparser.kevent import KD_BUF_SIZE
from pykdebugparser.trace_handlers.trace import TRACE_LOST_EVENTS

# bsd/sys/sysctl.h
CTL_KERN = 1
KERN_KDEBUG = 24
KERN_KDENABLE = 3
KERN_KDSETBUF = 4
KERN_KDGETBUF = 5
KERN_KDSETUP = 6
KERN_KDREMOVE = 7
KERN_KDREADTR = 10
KERN_KDTHRMAP = 12
KERN_KDPIDEX = 14
KERN_KDSET_TYPEFILTER = 22

# bsd/sys/kdebug_private.h
KDEBUG_ENABLE_TRACE = 0x1
KDBG_TYPENONE = 0x80000
KDBG_TYPEFILTER_BITMAP_SIZE = (256 * 256) // 8
KD_REGTYPE = struct.Struct('<5I')
KBUFINFO = struct.Struct('<iiIii')  # nkdbufs, nolog, flags, nkdthreads, bufid
DBG_TRACE = 7

# Kernel buffer size, in events. It holds what was traced while the reader was busy decoding.
DEFAULT_BUFFER_EVENTS = 1 << 20  # 64 MiB
# Events read by a single `KERN_KDREADTR`.
READ_EVENTS = 1 << 15
# Seconds to wait between reads that returned no events.
POLL_INTERVAL = 0.05

_LOST_EVENTS_DEBUGID = struct.pack('<I', TRACE_LOST_EVENTS)
_DEBUGID_OFFSET = 48

SysctlFunc = Callable[[list, Optional[bytearray]], int]


class TraceLagError(Exception):
    """Raised when a live trace falls further behind the system than it may."""

    def __init__(self, lag: float, max_lag: float):
        super().__init__(lag, max_lag)
        self.lag = lag
        self.max_lag = max_lag

    def __str__(self):
        return f'Fell {self.lag:.2f}s behind, more than the max lag ({self.max_lag:g}s)'


def typefilter(classes: Iterable[int] = (), subclasses: Iterable[int] = ()) -> bytes:
    """
    Build a kernel typefilter: a bitmap with a bit per class/subclass (`debugid >> 16`) to trace.
    :param classes: Classes to allow, each allows all of its subclasses.
    :param subclasses: Subclasses to allow, as `class << 8 | subclass`.
    :return: The bitmap, as `KERN_KDSET_TYPEFILTER` expects it.
    """
    bitmap = bytearray(KDBG_TYPEFILTER_BITMAP_SIZE)
    # The kernel always allows DBG_TRACE, it is what names new threads and processes.
    for class_ in {*classes, DBG_TRACE}:
        bitmap[class_ * 32:(class_ + 1) * 32] = b'\xff' * 32
    for csc in subclasses:
        bitmap[csc >> 3] |= 1 << (csc & 7)
    return bytes(bitmap)


class _Darwin:
    """The libSystem calls `HostTrace` needs."""

    class _TimebaseInfo(ctypes.Structure):
        _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]

    def __init__(self):
        if sys.platform != 'darwin':
            raise OSError(errno.ENOTSUP, 'Host tracing is only supported on macOS')
        self._libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        self._libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        self._libc.sysctl.restype = ctypes.c_int
        self._libc.mach_absolute_time.restype = ctypes.c_uint64

    def sysctl(self, mib: list, buffer: Optional[bytearray] = None) -> int:
        """
        Call sysctl with `buffer` as the old value (the kdebug sysctl uses it for both input and output).
        :return: The resulting old value length.
        """
        name = (ctypes.c_int * len(mib))(*mib)
        size = ctypes.c_size_t(0 if buffer is None else len(buffer))
        old = None if buffer is None else (ctypes.c_char * len(buffer)).from_buffer(buffer)
        if self._libc.sysctl(name, len(mib), old, ctypes.byref(size), None, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return size.value

    def timebase(self) -> tuple:
        info = self._TimebaseInfo()
        self._libc.mach_timebase_info(ctypes.byref(info))
        return info.numer, info.denom

    def mach_absolute_time(self) -> int:
        return self._libc.mach_absolute_time()


class HostTrace:
    """
    A live kdebug trace of this host, as a stream of a trace version 2.

    Use it as a context manager, and parse it with `PyKdebugParser` (after `configure_parser`)::

        with HostTrace(subclasses=[0x040c]) as trace:
            parser = PyKdebugParser()
            trace.configure_parser(parser)
            for line in parser.formatted_traces(trace):
                print(line)

    :param classes: Classes to trace, filtered by the kernel. Omit both filters for all.
    :param subclasses: Subclasses to trace (`class << 8 | subclass`), filtered by the kernel.
    :param buffer_events: Kernel buffer size, in events.
    :param exclude_pid: Process not to trace (by default the tracing process itself), `None` for none.
    :param max_lag: Skip the events of a read whose newest event is more than this many seconds old, so a reader slower
        than the system catches up instead of falling ever further behind. `None` never checks.
    :param skip_behind: Whether to skip the events that are more than `max_lag` old, or raise `TraceLagError`.
    :param on_skip: Called with the number of skipped events and how far behind the trace was, once per catch-up.
    :param on_wait: Called before waiting for events (everything traced so far was read), e.g. to flush buffered
        output.
    :param sysctl: Replaces the kdebug sysctl calls, for tests. Called with the MIB and a buffer.
    :param clock: Replaces the timebase and time information, a `(numer, denom, mach_absolute_time,
        usecs_since_epoch)` callable, for tests.
    """

    def __init__(self, classes: Iterable[int] = (), subclasses: Iterable[int] = (),
                 buffer_events: int = DEFAULT_BUFFER_EVENTS, exclude_pid: Optional[int] = -1,
                 sysctl: Optional[SysctlFunc] = None, clock: Optional[Callable[[], tuple]] = None,
                 poll_interval: float = POLL_INTERVAL, max_lag: Optional[float] = None,
                 on_skip: Optional[Callable[[int, float], None]] = None, on_wait: Optional[Callable[[], None]] = None,
                 skip_behind: bool = True):
        self.classes = list(classes)
        self.subclasses = list(subclasses)
        self.buffer_events = buffer_events
        self.exclude_pid = os.getpid() if exclude_pid == -1 else exclude_pid
        self.poll_interval = poll_interval
        self.max_lag = max_lag
        self.on_skip = on_skip
        self.on_wait = on_wait
        self.skip_behind = skip_behind
        self._darwin = None
        self._sysctl = sysctl
        self._clock = clock
        self._pending = memoryview(b'')
        self._read_buffer = bytearray(READ_EVENTS * KD_BUF_SIZE)
        self._started = False
        self.numer = None
        self.denom = None
        self.mach_absolute_time = None
        self.usecs_since_epoch = None
        self.timezone = None
        # Records read from the kernel.
        self.events = 0
        # Gaps the kernel reported (a TRACE_LOST_EVENTS record each): the buffer wrapped before it was read.
        self.lost_events = 0
        # Records skipped to catch up (see `max_lag`).
        self.skipped_events = 0
        self._skipping = 0  # events skipped in the current catch-up
        self._skipping_lag = 0.0

    def _kdebug(self, op: int, value: Optional[int] = None, buffer: Optional[bytearray] = None) -> int:
        mib = [CTL_KERN, KERN_KDEBUG, op] + ([] if value is None else [value])
        if self._sysctl is None:
            if self._darwin is None:
                self._darwin = _Darwin()
            self._sysctl = self._darwin.sysctl
        return self._sysctl(mib, buffer)

    def _time_info(self) -> tuple:
        if self._clock is not None:
            return self._clock()
        if self._darwin is None:
            self._darwin = _Darwin()
        numer, denom = self._darwin.timebase()
        return numer, denom, self._darwin.mach_absolute_time(), time.time_ns() // 1000

    def start(self):
        """Configure and enable tracing, stopping it on failure."""
        if self._started:
            return
        self._started = True
        try:
            # Start from a clean state, taking ownership of the trace facility (fails with EBUSY if another
            # process, such as ktrace or Instruments, is using it).
            self._kdebug(KERN_KDREMOVE)
            self._kdebug(KERN_KDSETBUF, self.buffer_events)
            self._kdebug(KERN_KDSETUP)
            if self.classes or self.subclasses:
                self._kdebug(KERN_KDSET_TYPEFILTER, buffer=bytearray(typefilter(self.classes, self.subclasses)))
            if self.exclude_pid is not None:
                exclude = KD_REGTYPE.pack(KDBG_TYPENONE, self.exclude_pid, 1, 0, 0)
                self._kdebug(KERN_KDPIDEX, buffer=bytearray(exclude))
            self.numer, self.denom, self.mach_absolute_time, self.usecs_since_epoch = self._time_info()
            self.timezone = datetime.now().astimezone().tzinfo
            # Enabling takes the threadmap.
            self._kdebug(KERN_KDENABLE, KDEBUG_ENABLE_TRACE)
            self._pending = memoryview(self._header(self._read_threadmap()))
        except BaseException:
            self.stop()
            raise

    def stop(self):
        """Disable and remove tracing, even if disabling fails."""
        if not self._started:
            return
        self._started = False
        try:
            self._kdebug(KERN_KDENABLE, 0)
        finally:
            self._kdebug(KERN_KDREMOVE)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def configure_parser(self, parser):
        """
        Set the time information of a `PyKdebugParser`, so it prints wall clock times, and parse the trace as live,
        so its memory stays flat however long it runs.
        """
        parser.live = True
        parser.numer = self.numer
        parser.denom = self.denom
        parser.mach_absolute_time = self.mach_absolute_time
        parser.usecs_since_epoch = self.usecs_since_epoch
        parser.timezone = self.timezone

    def _read_threadmap(self) -> bytes:
        info = bytearray(KBUFINFO.size)
        self._kdebug(KERN_KDGETBUF, buffer=info)
        threads = KBUFINFO.unpack(info)[3]
        threadmap = bytearray(threads * KdThreadmap.SIZE)
        try:
            size = self._kdebug(KERN_KDTHRMAP, buffer=threadmap)
        except OSError as e:
            if e.errno != errno.ENODATA:
                raise
            # No threadmap, threads will be named as they are created.
            size = 0
        return bytes(threadmap[:size - size % KdThreadmap.SIZE])

    @staticmethod
    def _header(threadmap: bytes) -> bytes:
        threads = len(threadmap) // KdThreadmap.SIZE
        header = RAW_VERSION2_BYTES + KdHeaderV2(number_of_threads=threads, tod_secs=0, tod_usecs=0,
                                                 flags=KDBG_LP64, tick_frequency=0).build() + threadmap
        # The events start at a 4 KiB boundary.
        return header + bytes(-len(header) % 0x1000)

    def _now(self) -> int:
        """The current mach absolute time, the clock of event timestamps."""
        if self._clock is not None:
            return self._clock()[2]
        return self._darwin.mach_absolute_time()

    def _read_events(self) -> bytes:
        """Read the events traced so far, waiting until there is at least one (that isn't skipped)."""
        buffer = self._read_buffer
        while True:
            if not self._started:
                return b''
            count = self._kdebug(KERN_KDREADTR, buffer=buffer)
            if not count:
                if self.on_wait is not None:
                    self.on_wait()
                time.sleep(self.poll_interval)
                continue
            size = count * KD_BUF_SIZE
            self.events += count
            index = buffer.find(_LOST_EVENTS_DEBUGID, 0, size)
            while index != -1:
                if index % KD_BUF_SIZE == _DEBUGID_OFFSET:
                    self.lost_events += 1
                index = buffer.find(_LOST_EVENTS_DEBUGID, index + 1, size)
            if not self._is_behind(count):
                break
        self._report_skip()
        return bytes(memoryview(buffer)[:size])

    def _is_behind(self, count: int) -> bool:
        """Whether the newest of the read events is more than `max_lag` old, counting them as skipped if so."""
        if self.max_lag is None:
            return False
        newest = struct.unpack_from('<Q', self._read_buffer, (count - 1) * KD_BUF_SIZE)[0]
        lag = (self._now() - newest) * self.numer / self.denom / 1e9
        if lag <= self.max_lag:
            return False
        if not self.skip_behind:
            raise TraceLagError(lag, self.max_lag)
        self._skipping += count
        self._skipping_lag = max(self._skipping_lag, lag)
        return True

    def _report_skip(self):
        if not self._skipping:
            return
        self.skipped_events += self._skipping
        if self.on_skip is not None:
            self.on_skip(self._skipping, self._skipping_lag)
        self._skipping = 0
        self._skipping_lag = 0.0

    def read1(self, size: int = -1) -> bytes:
        """Read up to `size` bytes, waiting only if nothing was read yet."""
        if not self._pending:
            self._pending = memoryview(self._read_events())
        if size < 0:
            size = len(self._pending)
        data = bytes(self._pending[:size])
        self._pending = self._pending[size:]
        return data

    def read(self, size: int = -1) -> bytes:
        """Read `size` bytes (waiting for them), only returning less when tracing stopped."""
        if size < 0:
            return self.read1()
        chunks = []
        while size > 0:
            chunk = self.read1(size)
            if not chunk:
                break
            chunks.append(chunk)
            size -= len(chunk)
        return b''.join(chunks)

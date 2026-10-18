from collections import namedtuple
import enum
import struct

KDBG_EVENTID_MASK = 0xfffffffc
KDBG_FUNC_MASK = 0x00000003
KD_BUF_FORMAT = '<Q32sQIIQ'
# Same layout as `KD_BUF_FORMAT`, with the 32 bytes of arguments unpacked as 4 64-bit values.
KD_BUF_STRUCT = struct.Struct('<QQQQQQIIQ')
KD_BUF_SIZE = KD_BUF_STRUCT.size
Kevent = namedtuple('Kevent', ['timestamp', 'data', 'values', 'tid', 'debugid', 'eventid', 'func_qualifier'])


class DgbFuncQual(enum.Enum):
    """
    Event's role in the trace.
    """
    DBG_FUNC_NONE = 0
    DBG_FUNC_START = 1
    DBG_FUNC_END = 2
    DBG_FUNC_ALL = 3


def from_kd_buf(kd_buf: bytes) -> Kevent:
    """
    Create a Kevent object from a kd_buf kevent's struct.
    :param kd_buf: Buffer of kd_buf kevent's struct.
    :return: Parsed kevent.
    """
    timestamp, arg0, arg1, arg2, arg3, tid, debugid, cpuid, unused = KD_BUF_STRUCT.unpack(kd_buf)
    return Kevent(timestamp, kd_buf[8:40], (arg0, arg1, arg2, arg3), tid, debugid, debugid & KDBG_EVENTID_MASK,
                  debugid & KDBG_FUNC_MASK)


def from_kd_bufs(kd_bufs: bytes):
    """
    Create Kevent objects from consecutive kd_buf kevent's structs.
    :param kd_bufs: Buffer of kd_buf kevent's structs, its length must be a multiple of the struct size.
    :return: Generator of parsed kevents.
    """
    new_kevent = tuple.__new__  # Skips the namedtuple's Python-level __new__, the result is identical.
    offset = 8
    for timestamp, arg0, arg1, arg2, arg3, tid, debugid, cpuid, unused in KD_BUF_STRUCT.iter_unpack(kd_bufs):
        yield new_kevent(Kevent, (timestamp, kd_bufs[offset:offset + 32], (arg0, arg1, arg2, arg3), tid, debugid,
                                  debugid & KDBG_EVENTID_MASK, debugid & KDBG_FUNC_MASK))
        offset += KD_BUF_SIZE

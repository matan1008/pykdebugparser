import struct

from pykdebugparser.kevent import Kevent


def test_disk_io(traces_parser):
    events = [
        Kevent(timestamp=72658011146,
               data=(b'\x96\xd6\x00\x00\x00\x00\x00\x00\x02\x00\x00\x03\x00\x00\x00\x00\x7f\x02'
                     b'\x00\x00\x00\x00\x00\x00\x9b\x00\x00\x00\x00\x00\x00\x00'),
               values=(54934, 50331650, 639, 155),
               tid=54934, debugid=50462720, eventid=50462720, func_qualifier=0),
        Kevent(timestamp=72658011185,
               data=(b'\x96\xd6\x00\x00\x00\x00\x00\x001\x9f\x14\x1c\xb1\xff\xe1\xae\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(54934, 12601634368504766257, 0, 0),
               tid=54934, debugid=50462724, eventid=50462724, func_qualifier=0),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'P_WrData, dev: 3,2, blkno: 0x27f, size: 155, resid: 0, error: 0'


def test_disk_io_completion_without_issue(traces_parser):
    # The I/O was issued before the trace started: only the completion is known.
    done = (0xffffff8000001234, 0xffffff8000005678, 0, 5)
    events = [
        Kevent(timestamp=1000, data=struct.pack('<4Q', *done), values=done, tid=99, debugid=0x302000c,
               eventid=0x302000c, func_qualifier=0),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'P_RdData, resid: 0, error: 5'

from datetime import datetime, timedelta, timezone
from io import BytesIO
import struct

import pytest

from pykdebugparser.kd_buf_parser import RAW_VERSION2_BYTES
from pykdebugparser.kevent import Kevent
from pykdebugparser.pykdebugparser import PyKdebugParser


def test_kevents():
    events_buf = RAW_VERSION2_BYTES + b'\x00' * 0x11c
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
    events_buf = RAW_VERSION2_BYTES + b'\x00' * 0x11c
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
    events_buf = RAW_VERSION2_BYTES + b'\x00' * 0x11c
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

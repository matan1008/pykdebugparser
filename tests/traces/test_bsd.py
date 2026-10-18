import struct

import pytest

from pykdebugparser.kevent import Kevent


def test_read(traces_parser):
    events = [
        Kevent(timestamp=15783429453,
               data=(b'\x07\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xf1\x1b\x01\x00\x00\x00\xd6c'
                     b'\x00\x00\x00\x00\x00\x00h\xd8:m\x01\x00\x00\x00'),
               values=(7, 4763795456, 25558, 6127540328), tid=7573, debugid=67895309, eventid=67895308,
               func_qualifier=1),
        Kevent(timestamp=15783456070,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\xd6c\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 25558, 0, 144), tid=7573, debugid=67895310, eventid=67895308, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'read(7, 0x11bf1c000, 25558), count: 25558'


def test_csops_audittoken_16(traces_parser):
    events = [
        Kevent(timestamp=1805610285184,
               data=(b'C\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xa0&\xa1m'
                     b'\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00'),
               values=(67, 16, 6134245024, 8), tid=1599, debugid=67895977, eventid=67895976, func_qualifier=1),
        Kevent(timestamp=1805610285735,
               data=(b'"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x00\x00\x00'),
               values=(34, 0, 0, 67), tid=1599, debugid=67895978, eventid=67895976, func_qualifier=2)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == 'csops_audittoken(67, CS_OPS_16, 0x16da126a0, 8), errno: ERANGE(34)'


@pytest.mark.parametrize('domain, expected', [
    (2, 'socket(AF_INET, SOCK_STREAM, 0), fd: 5'),
    # AF_MULTIPATH, which only XNU's private socket header defines.
    (39, 'socket(39, SOCK_STREAM, 0), fd: 5'),
])
def test_socket(traces_parser, domain, expected):
    start = (domain, 1, 0, 0)
    end = (0, 5, 0, 0)
    events = [
        Kevent(timestamp=1000, data=struct.pack('<4Q', *start), values=start, tid=7573, debugid=0x40c0185,
               eventid=0x40c0184, func_qualifier=1),
        Kevent(timestamp=2000, data=struct.pack('<4Q', *end), values=end, tid=7573, debugid=0x40c0186,
               eventid=0x40c0184, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == expected


def test_openat_dprotected_np(traces_parser):
    events = [
        Kevent(timestamp=22719745585,
               data=(b'@\x00\x00\x00\x00\x00\x00\x00\xb0X_o\x01\x00\x00\x00\x02\n'
                     b'\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00'),
               values=(64, 6163486896, 2562, 3),
               tid=46291, debugid=67896169, eventid=67896168, func_qualifier=1),
        Kevent(timestamp=22719746089,
               data=(b"-6P\xf2\x8b'/\x0eATXSuggest"
                     b'edPagesHomeScr'),
               values=(1022079122455672365, 7306922674039051329, 7306915918341567603, 8242523438110951539),
               tid=46291, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=22719746092,
               data=(b'eenModificationsMe'
                     b'tricsLogger\x00\x00\x00'),
               values=(7379539893626496357, 8317708060514673513, 5508856073747195213, 491327547247),
               tid=46291, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=22719748695,
               data=(b'\x17\xb9\xef-jf\x07\xeeATXSuggest'
                     b'edPagesHomeScr'),
               values=(17151790312087075095, 7306922674039051329, 7306915918341567603, 8242523438110951539),
               tid=46291, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=22719748698,
               data=(b'eenModificationsMe'
                     b'tricsLogger\x00\x00\x00'),
               values=(7379539893626496357, 8317708060514673513, 5508856073747195213, 491327547247),
               tid=46291, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=22719749041,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00A\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xdc\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 65, 0, 220),
               tid=46291, debugid=67896170, eventid=67896168, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == ('openat_dprotected_np(64, "ATXSuggestedPagesHomeScreenModificationsMetricsLogger", '
                            'O_RDWR | O_CREAT | O_EXCL, 3), fd: 65')


def test_ledger(traces_parser):
    events = [
        Kevent(timestamp=22823624434,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\xfc\x04\x00\x00\x00\x00\x00\x00\xd0\xa3'
                     b'\x16k\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 1276, 6091613136, 0),
               tid=46388, debugid=67896789, eventid=67896788, func_qualifier=1),
        Kevent(timestamp=22823624520,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00W\x00\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 87),
               tid=46388, debugid=67896790, eventid=67896788, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'ledger(LEDGER_INFO, 1276, 0x16b16a3d0, 0x0)'


def test_sys_crossarch_trap(traces_parser):
    events = [
        Kevent(timestamp=22825436759,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa8\xb14m\x01\x00\x00\x00'),
               values=(0, 0, 0, 6127137192),
               tid=46656, debugid=67895449, eventid=67895448, func_qualifier=1),
        Kevent(timestamp=22825436767,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x03\x05\x00\x00\x00\x00\x00\x00'),
               values=(1, 0, 0, 1283),
               tid=46656, debugid=67895450, eventid=67895448, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'crossarch_trap(0), errno: EPERM(1)'


def test_map_with_linking_np(traces_parser):
    events = [
        Kevent(timestamp=22825468433,
               data=(b'@K4m\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00pK'
                     b'4m\x01\x00\x00\x00\x90\x01\x00\x00\x00\x00\x00\x00'),
               values=(6127110976, 1, 6127111024, 400),
               tid=46656, debugid=67897497, eventid=67897496, func_qualifier=1),
        Kevent(timestamp=22825468559,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x03\x05\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 1283),
               tid=46656, debugid=67897498, eventid=67897496, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'map_with_linking_np(0x16d344b40, 1, 0x16d344b70, 400)'


def test_mkfifoat(traces_parser):
    events = [
        Kevent(timestamp=7749160545366,
               data=(b'\xfe\xff\xff\xff\xff\xff\xff\xff\xdc\xc4\x96\x02\x01\x00\x00\x00\xa4\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(18446744073709551614, 4338402524, 420, 0),
               tid=2325336, debugid=67897509, eventid=67897508, func_qualifier=1),
        Kevent(timestamp=7749160545748,
               data=(b'{}\xa1\xa5\x8f\x90\xf4Pprivate/va'
                     b'r/tmp/pkd_fifo'),
               values=(5833446363985182075, 3415263854377661040, 3418352462953865590, 8027219274242485104),
               tid=2325336, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=7749160545755,
               data=(b'1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(49, 0, 0, 0),
               tid=2325336, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=7749160547092,
               data=(b'\x99v\xbc\x08\xd9\xb3\xfb(private/va'
                     b'r/tmp/pkd_fifo'),
               values=(2953151725407336089, 3415263854377661040, 3418352462953865590, 8027219274242485104),
               tid=2325336, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=7749160547095,
               data=(b'1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(49, 0, 0, 0),
               tid=2325336, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=7749160547130,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67897510, eventid=67897508, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'mkfifoat(-2, "private/var/tmp/pkd_fifo1", S_IROTH | S_IRGRP | S_IWUSR | S_IRUSR)'


def test_mknodat(traces_parser):
    events = [
        Kevent(timestamp=7749160547151,
               data=(b'\xfe\xff\xff\xff\xff\xff\xff\xff\xeb\xc4\x96\x02\x01\x00\x00\x00\x80\x11'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(18446744073709551614, 4338402539, 4480, 0),
               tid=2325336, debugid=67897513, eventid=67897512, func_qualifier=1),
        Kevent(timestamp=7749160547334,
               data=(b'{}\xa1\xa5\x8f\x90\xf4Pprivate/va'
                     b'r/tmp/pkd_fifo'),
               values=(5833446363985182075, 3415263854377661040, 3418352462953865590, 8027219274242485104),
               tid=2325336, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=7749160547338,
               data=(b'2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(50, 0, 0, 0),
               tid=2325336, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=7749160547938,
               data=(b'A\x8f\x80JF\xde\xc6\x81private/va'
                     b'r/tmp/pkd_fifo'),
               values=(9351406069760429889, 3415263854377661040, 3418352462953865590, 8027219274242485104),
               tid=2325336, debugid=50397329, eventid=50397328, func_qualifier=1),
        Kevent(timestamp=7749160547941,
               data=(b'2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(50, 0, 0, 0),
               tid=2325336, debugid=50397330, eventid=50397328, func_qualifier=2),
        Kevent(timestamp=7749160547952,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67897514, eventid=67897512, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'mknodat(-2, "private/var/tmp/pkd_fifo2", S_IWUSR | S_IRUSR | S_IFIFO, 0)'


def test_freadlink(traces_parser):
    events = [
        Kevent(timestamp=7749160549384,
               data=(b'\x03\x00\x00\x00\x00\x00\x00\x00(rIm\x01\x00\x00\x00\x00\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(3, 6128497192, 256, 0),
               tid=2325336, debugid=67897501, eventid=67897500, func_qualifier=1),
        Kevent(timestamp=7749160549620,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 15, 0, 48648),
               tid=2325336, debugid=67897502, eventid=67897500, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'freadlink(3, 0x16d497228, 256), count: 15'


def test_funmount(traces_parser):
    events = [
        Kevent(timestamp=7749160549633,
               data=(b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(3, 0, 256, 0),
               tid=2325336, debugid=67895953, eventid=67895952, func_qualifier=1),
        Kevent(timestamp=7749160550808,
               data=(b'\x16\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(22, 0, 0, 48648),
               tid=2325336, debugid=67895954, eventid=67895952, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'funmount(3, 0), errno: EINVAL(22)'


def test_ungraftdmg(traces_parser):
    events = [
        Kevent(timestamp=7749160551029,
               data=(b'&\xc5\x96\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(4338402598, 0, 256, 0),
               tid=2325336, debugid=67897517, eventid=67897516, func_qualifier=1),
        Kevent(timestamp=7749160551136,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(1, 0, 0, 48648),
               tid=2325336, debugid=67897518, eventid=67897516, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'ungraftdmg("", 0), errno: EPERM(1)'


def test_sys_coalition_policy_get(traces_parser):
    events = [
        Kevent(timestamp=7749160551150,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1, 0, 256, 0),
               tid=2325336, debugid=67897525, eventid=67897524, func_qualifier=1),
        Kevent(timestamp=7749160551315,
               data=(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(1, 0, 0, 48648),
               tid=2325336, debugid=67897526, eventid=67897524, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'coalition_policy_get(1, 0), errno: EPERM(1)'


def test_aio_read(traces_parser):
    events = [
        Kevent(timestamp=7749160587869,
               data=(b'\x98qIm\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\xff'
                     b'\xff\xff\xff\xff\xff\xff\xa8qIm\x01\x00\x00\x00'),
               values=(6128497048, 0, 18446744073709551592, 6128497064),
               tid=2325336, debugid=67896569, eventid=67896568, func_qualifier=1),
        Kevent(timestamp=7749160589254,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896570, eventid=67896568, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_read(0x16d497198)'


def test_aio_suspend(traces_parser):
    events = [
        Kevent(timestamp=7749160589279,
               data=(b' rIm\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa8qIm\x01\x00\x00\x00'),
               values=(6128497184, 1, 0, 6128497064),
               tid=2325336, debugid=67896557, eventid=67896556, func_qualifier=1),
        Kevent(timestamp=7749160590478,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896558, eventid=67896556, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_suspend(0x16d497220, 1, 0x0)'


def test_aio_error(traces_parser):
    events = [
        Kevent(timestamp=7749160590529,
               data=(b'\x98qIm\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa8qIm\x01\x00\x00\x00'),
               values=(6128497048, 0, 0, 6128497064),
               tid=2325336, debugid=67896565, eventid=67896564, func_qualifier=1),
        Kevent(timestamp=7749160590543,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896566, eventid=67896564, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_error(0x16d497198), error: 0'


def test_aio_return(traces_parser):
    events = [
        Kevent(timestamp=7749160590556,
               data=(b'\x98qIm\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa8qIm\x01\x00\x00\x00'),
               values=(6128497048, 0, 0, 6128497064),
               tid=2325336, debugid=67896553, eventid=67896552, func_qualifier=1),
        Kevent(timestamp=7749160590589,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 9, 0, 48648),
               tid=2325336, debugid=67896554, eventid=67896552, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_return(0x16d497198), count: 9'


def test_lio_listio(traces_parser):
    events = [
        Kevent(timestamp=7749160590609,
               data=(b'\x02\x00\x00\x00\x00\x00\x00\x00\x18rIm\x01\x00\x00\x00\x01\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(2, 6128497176, 1, 0),
               tid=2325336, debugid=67896577, eventid=67896576, func_qualifier=1),
        Kevent(timestamp=7749160592360,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896578, eventid=67896576, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'lio_listio(2, 0x16d497218, 1, 0x0)'


def test_aio_fsync(traces_parser):
    events = [
        Kevent(timestamp=7749160592479,
               data=(b'\x80\x00\x00\x00\x00\x00\x00\x00\x98qIm\x01\x00\x00\x00\x01\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(128, 6128497048, 1, 0),
               tid=2325336, debugid=67896549, eventid=67896548, func_qualifier=1),
        Kevent(timestamp=7749160592791,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896550, eventid=67896548, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_fsync(128, 0x16d497198)'


def test_aio_cancel(traces_parser):
    events = [
        Kevent(timestamp=7749160621419,
               data=(b'\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(3, 0, 0, 0),
               tid=2325336, debugid=67896561, eventid=67896560, func_qualifier=1),
        Kevent(timestamp=7749160621508,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 1, 0, 48648),
               tid=2325336, debugid=67896562, eventid=67896560, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'aio_cancel(3, 0x0), return: 1'


def test_sigwait(traces_parser):
    events = [
        Kevent(timestamp=7749161173238,
               data=(b'\x8cqIm\x01\x00\x00\x00\x88qIm\x01\x00\x00\x00\x01\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(6128497036, 6128497032, 1, 0),
               tid=2325336, debugid=67896617, eventid=67896616, func_qualifier=1),
        Kevent(timestamp=7749161173258,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 48648),
               tid=2325336, debugid=67896618, eventid=67896616, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'sigwait(0x16d49718c, 0x16d497188)'


def test_wait4(traces_parser):
    events = [
        Kevent(timestamp=7749234955635,
               data=(b'\xff\xff\xff\xff\x00\x00\x00\x00\xec\xe3_k\x01\x00\x00\x00\x01\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(4294967295, 6096413676, 1, 0),
               tid=2324735, debugid=67895325, eventid=67895324, func_qualifier=1),
        Kevent(timestamp=7749234955901,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x08\xbe\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xa5\xbd\x00\x00\x00\x00\x00\x00'),
               values=(0, 48648, 0, 48549),
               tid=2324735, debugid=67895326, eventid=67895324, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'wait4(-1, 0x16b5fe3ec, 1, 0x0), pid: 48648'


@pytest.mark.parametrize('name, args, end, expected', [
    ('BSC_sys_dup3', (3, 10, 0x1000000, 0), (0, 10, 0, 0), 'dup3(3, 10, 16777216), fd: 10'),
    ('BSC_pipe2', (0x16b000000, 0x1000000, 0, 0), (0, 0, 0, 0), 'pipe2(0x16b000000, 16777216)'),
    ('BSC_getumask', (0, 0, 0, 0), (0, 0o22, 0, 0), 'getumask(), mask: 18'),
    ('BSC_aio_readv', (0x16b000000, 0, 0, 0), (0, 0, 0, 0), 'aio_readv(0x16b000000)'),
    ('BSC_aio_writev', (0x16b000000, 0, 0, 0), (0, 0, 0, 0), 'aio_writev(0x16b000000)'),
    ('BSC_sys_coalition_policy_set', (1, 0, 1, 0), (1, 0, 0, 0), 'coalition_policy_set(1, 0, 1), errno: EPERM(1)'),
    ('BSC_oslog_coproc_reg', (0x16b000000, 0x16b000100, 32, 0), (0, 0, 0, 0),
     'oslog_coproc_reg(0x16b000000, 0x16b000100, 32)'),
    ('BSC_oslog_coproc', (0x16b000000, 64, 1, 0x16b000100), (0, 0, 0, 0),
     'oslog_coproc(0x16b000000, 64, 1, 0x16b000100)'),
])
def test_syscall_args(traces_parser, name, args, end, expected):
    eventid = next(code for code, trace_name in traces_parser.trace_codes.items() if trace_name == name)
    events = [
        Kevent(timestamp=1, data=struct.pack('<4Q', *args), values=args, tid=1, debugid=eventid | 1, eventid=eventid,
               func_qualifier=1),
        Kevent(timestamp=2, data=struct.pack('<4Q', *end), values=end, tid=1, debugid=eventid | 2, eventid=eventid,
               func_qualifier=2),
    ]
    assert str(list(traces_parser.feed_generator(events))[0]) == expected


def test_fchflagsat(traces_parser):
    eventid = next(code for code, trace_name in traces_parser.trace_codes.items() if trace_name == 'BSC_fchflagsat')
    lookup = struct.pack('<Q', 0x1234) + b'private/var/tmp/f'.ljust(24, b'\x00')
    args = (0xfffffffe, 0x16b000000, 0x2, 0)
    events = [
        Kevent(timestamp=1, data=struct.pack('<4Q', *args), values=args, tid=1, debugid=eventid | 1, eventid=eventid,
               func_qualifier=1),
        Kevent(timestamp=2, data=lookup, values=struct.unpack('<4Q', lookup), tid=1, debugid=0x3010093,
               eventid=0x3010090, func_qualifier=3),
        Kevent(timestamp=3, data=bytes(32), values=(0, 0, 0, 0), tid=1, debugid=eventid | 2, eventid=eventid,
               func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'fchflagsat(-2, "private/var/tmp/f", UF_IMMUTABLE, 0)'


def test_proc_exit(traces_parser):
    events = [
        Kevent(timestamp=73004319714,
               data=(b'\xdf\x04\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1247, 9, 0, 0),
               tid=55798, debugid=67174405, eventid=67174404, func_qualifier=1),
        Kevent(timestamp=73004327671,
               data=(b'\xdf\x04\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(1247, 9, 0, 0),
               tid=55798, debugid=67174406, eventid=67174404, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'proc_exit, pid: 1247, signal: SIGKILL'


def test_exit(traces_parser):
    events = [
        Kevent(timestamp=73094371729,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xa8 '
                     b'\x01\x00\x00\x00\x00\x00\xd0\xb0\xdc\xf4\x01\x00\x00\x00'),
               values=(0, 1, 73896, 8403071184),
               tid=56116, debugid=67895301, eventid=67895300, func_qualifier=1),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'exit(0)'


def test_bsdthread_terminate(traces_parser):
    events = [
        Kevent(timestamp=72658811835,
               data=(b'\x00\x80\xack\x01\x00\x00\x00\x00\xc0\x08\x00\x00\x00\x00\x00\x03\x14'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(6101434368, 573440, 5123, 0),
               tid=56115, debugid=67896741, eventid=67896740, func_qualifier=1),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'bsdthread_terminate(0x16bac8000, 0x8c000, 5123, 0)'


@pytest.mark.parametrize('status, expected', [
    (0x100, 'proc_exit, pid: 42, exit code: 1'),
    (0x0, 'proc_exit, pid: 42, exit code: 0'),
    (0x86, 'proc_exit, pid: 42, signal: SIGABRT, core dumped'),
])
def test_proc_exit_status(traces_parser, status, expected):
    start = (42, status, 0, 0)
    events = [
        Kevent(timestamp=1000, data=struct.pack('<4Q', *start), values=start, tid=7573, debugid=0x4010005,
               eventid=0x4010004, func_qualifier=1),
        Kevent(timestamp=2000, data=struct.pack('<4Q', *start), values=start, tid=7573, debugid=0x4010006,
               eventid=0x4010004, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == expected


def test_pthread_kill(traces_parser):
    events = [
        Kevent(timestamp=8676671100749,
               data=(b'\x03\x01\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00\xfcr'
                     b'\xd5k\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'),
               values=(259, 30, 6104118012, 1),
               tid=2694815, debugid=67896609, eventid=67896608, func_qualifier=1),
        Kevent(timestamp=8676671100888,
               data=(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xce~\x01\x00\x00\x00\x00\x00'),
               values=(0, 0, 0, 97998),
               tid=2694815, debugid=67896610, eventid=67896608, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'pthread_kill(259, SIGUSR1)'


def test_sigreturn(traces_parser):
    events = [
        Kevent(timestamp=8676671102970,
               data=(b'\xc8n\xd5k\x01\x00\x00\x00\x1e\x00\x00\x00\x00\x00\x00\x00l.'
                     b'Q]\xaa\xd6\xfc\x17`n\xd5k\x01\x00\x00\x00'),
               values=(6104116936, 30, 1728492384201813612, 6104116832),
               tid=2694815, debugid=67896033, eventid=67896032, func_qualifier=1),
        Kevent(timestamp=8676671103062,
               data=(b'\xfe\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\xce~\x01\x00\x00\x00\x00\x00'),
               values=(18446744073709551614, 0, 0, 97998),
               tid=2694815, debugid=67896034, eventid=67896032, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[-1]) == 'sigreturn(0x16bd56ec8, 30, 0x17fcd6aa5d512e6c), errno: EJUSTRETURN(-2)'


@pytest.mark.parametrize('eventid, start, end, expected', [
    # launchd signaling a process group, as `kill(-pgid, sig)` does: pid_t is a C int.
    (0x40c0094, (4294965818, 15, 1, 0), (1, 0, 0, 0), 'kill(-1478, SIGTERM), errno: EPERM(1)'),
    # Signal 0 only checks that the process exists.
    (0x40c0094, (97998, 0, 0, 0), (0, 0, 0, 0), 'kill(97998, 0)'),
    (0x40c0148, (0, 0, 0, 0), (0, 0, 0, 0), 'setpgid(0, 0)'),
    (0x40c025c, (4294967295, 0, 0, 0), (3, 0, 0, 0), 'getpgid(-1), errno: ESRCH(3)'),
])
def test_signed_pid(traces_parser, eventid, start, end, expected):
    events = [
        Kevent(timestamp=1000, data=struct.pack('<4Q', *start), values=start, tid=1, debugid=eventid | 1,
               eventid=eventid, func_qualifier=1),
        Kevent(timestamp=2000, data=struct.pack('<4Q', *end), values=end, tid=1, debugid=eventid | 2,
               eventid=eventid, func_qualifier=2),
    ]
    ret = list(traces_parser.feed_generator(events))
    assert str(ret[0]) == expected

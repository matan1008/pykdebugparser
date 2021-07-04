from pykdebugparser.kevent import Kevent
from pykdebugparser.trace_handlers.perf import CallstackFlag, KperfTiState


def test_thd_data(traces_parser):
    events = [
        Kevent(timestamp=15773877915,
               data=(b'P\x00\x00\x00\x00\x00\x00\x00\x9d\x04\x00\x00\x00\x00\x00\x00\x00'
                     b'\xfa\x17\x05\x01\x00\x00\x00\x03\x00\xfc\xff\x00\x00\x00\x00'),
               values=(80, 1181, 4380424704, 4294705155), tid=1181, debugid=620822532, eventid=620822532,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert len(ret) == 1
    thd_data = ret[0]
    assert thd_data.pid == 80
    assert thd_data.tid == 1181
    assert thd_data.dq_addr == 0x10517fa00
    assert thd_data.runmode == [KperfTiState.KPERF_TI_RUNNING, KperfTiState.KPERF_TI_RUNNABLE]


def test_thd_cswitch(traces_parser):
    events = [
        Kevent(timestamp=15779569737,
               data=(b'`\x10\x00\x00\x00\x00\x00\x00P\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(4192, 80, 0, 0), tid=4192, debugid=620822548, eventid=620822548, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert len(ret) == 1
    thd_cswitch = ret[0]
    assert thd_cswitch.tid == 4192
    assert thd_cswitch.pid == 80


def test_stk_udata(traces_parser):
    events = [
        Kevent(timestamp=15771902115,
               data=(b'\x94\xec\x12\x93\x01\x00\x00\x00\xa8\xf8\x12\x93\x01\x00\x00\x008\x93'
                     b'\x13\x93\x01\x00\x00\x00\xa4\xa5\xbe\xd9\x01\x00\x00\x00'),
               values=(6762458260, 6762461352, 6762500920, 7948117412), tid=7565, debugid=620888080, eventid=620888080,
               func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert len(ret) == 1
    stk_udata = ret[0]
    assert stk_udata.frames == [0x19312ec94, 0x19312f8a8, 0x193139338, 0x1d9bea5a4]


def test_stk_uhdr(traces_parser):
    events = [
        Kevent(timestamp=15772304192,
               data=(b'E\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
               values=(69, 7, 0, 0), tid=6206, debugid=620888088, eventid=620888088, func_qualifier=0)
    ]
    ret = list(traces_parser.feed_generator(events))
    assert len(ret) == 1
    stk_uhdr = ret[0]
    assert stk_uhdr.flags == [CallstackFlag.CALLSTACK_VALID, CallstackFlag.CALLSTACK_64BIT,
                              CallstackFlag.CALLSTACK_KERNEL_WORDS]
    assert stk_uhdr.nframes == 7

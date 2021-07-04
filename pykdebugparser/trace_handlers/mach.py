import ctypes
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import List


class AsynchronousSystemTrapsReason(Enum):
    AST_NONE = 0x00
    AST_PREEMPT = 0x01
    AST_QUANTUM = 0x02
    AST_URGENT = 0x04
    AST_HANDOFF = 0x08
    AST_YIELD = 0x10
    AST_APC = 0x20
    AST_LEDGER = 0x40
    AST_BSD = 0x80
    AST_KPERF = 0x100
    AST_MACF = 0x200
    AST_RESET_PCS = 0x400
    AST_ARCADE = 0x800
    AST_GUARD = 0x1000
    AST_TELEMETRY_USER = 0x2000
    AST_TELEMETRY_KERNEL = 0x4000
    AST_TELEMETRY_PMI = 0x8000
    AST_SFI = 0x10000
    AST_DTRACE = 0x20000
    AST_TELEMETRY_IO = 0x40000
    AST_KEVENT = 0x80000
    AST_REBALANCE = 0x100000
    AST_UNQUIESCE = 0x200000


def to_ast_reasons(flags: int):
    if not flags:
        return [AsynchronousSystemTrapsReason.AST_NONE]
    else:
        return [r for r in AsynchronousSystemTrapsReason if r.value & flags]


# osfmk/arm64/proc_reg.h

ESR_EC_SHIFT = 26


class ExceptionSyndromeRegisterClass(Enum):
    ESR_EC_UNCATEGORIZED = 0x00
    ESR_EC_WFI_WFE = 0x01
    ESR_EC_MCR_MRC_CP15_TRAP = 0x03
    ESR_EC_MCRR_MRRC_CP15_TRAP = 0x04
    ESR_EC_MCR_MRC_CP14_TRAP = 0x05
    ESR_EC_LDC_STC_CP14_TRAP = 0x06
    ESR_EC_TRAP_SIMD_FP = 0x07
    ESR_EC_PTRAUTH_INSTR_TRAP = 0x09
    ESR_EC_MCRR_MRRC_CP14_TRAP = 0x0c
    ESR_EC_ILLEGAL_INSTR_SET = 0x0e
    ESR_EC_SVC_32 = 0x11
    ESR_EC_SVC_64 = 0x15
    ESR_EC_MSR_TRAP = 0x18
    ESR_EC_IABORT_EL0 = 0x20
    ESR_EC_IABORT_EL1 = 0x21
    ESR_EC_PC_ALIGN = 0x22
    ESR_EC_DABORT_EL0 = 0x24
    ESR_EC_DABORT_EL1 = 0x25
    ESR_EC_SP_ALIGN = 0x26
    ESR_EC_FLOATING_POINT_32 = 0x28
    ESR_EC_FLOATING_POINT_64 = 0x2C
    ESR_EC_BKPT_REG_MATCH_EL0 = 0x30
    ESR_EC_BKPT_REG_MATCH_EL1 = 0x31
    ESR_EC_SW_STEP_DEBUG_EL0 = 0x32
    ESR_EC_SW_STEP_DEBUG_EL1 = 0x33
    ESR_EC_WATCHPT_MATCH_EL0 = 0x34
    ESR_EC_WATCHPT_MATCH_EL1 = 0x35
    ESR_EC_BKPT_AARCH32 = 0x38
    ESR_EC_BRK_AARCH64 = 0x3C


class ThreadState(Enum):
    TH_WAIT = 0x01
    TH_SUSP = 0x02
    TH_RUN = 0x04
    TH_UNINT = 0x08
    TH_TERMINATE = 0x10
    TH_TERMINATE2 = 0x20
    TH_WAIT_REPORT = 0x40
    TH_IDLE = 0x80


def to_thread_state(flags: int):
    return [s for s in ThreadState if s.value & flags]


class InterruptType(Enum):
    DBG_INTR_TYPE_UNKNOWN = 0x0
    DBG_INTR_TYPE_IPI = 0x1
    DBG_INTR_TYPE_TIMER = 0x2
    DBG_INTR_TYPE_OTHER = 0x3
    DBG_INTR_TYPE_PMI = 0x4


class ProcessState(Enum):
    PROCESSOR_OFF_LINE = 0
    PROCESSOR_SHUTDOWN = 1
    PROCESSOR_START = 2
    PROCESSOR_UNUSED = 3
    PROCESSOR_IDLE = 4
    PROCESSOR_DISPATCHING = 5
    PROCESSOR_RUNNING = 6


class DbgVmFaultType(Enum):
    DBG_ZERO_FILL_FAULT = 1
    DBG_PAGEIN_FAULT = 2
    DBG_COW_FAULT = 3
    DBG_CACHE_HIT_FAULT = 4
    DBG_NZF_PAGE_FAULT = 5
    DBG_GUARD_FAULT = 6
    DBG_PAGEINV_FAULT = 7
    DBG_PAGEIND_FAULT = 8
    DBG_COMPRESSOR_FAULT = 9
    DBG_COMPRESSOR_SWAPIN_FAULT = 10
    DBG_COR_FAULT = 11


class VmProtection(Enum):
    VM_PROT_NONE = 0x00
    VM_PROT_READ = 0x01
    VM_PROT_WRITE = 0x02
    VM_PROT_EXECUTE = 0x04
    VM_PROT_NO_CHANGE = 0x08
    VM_PROT_COPY = 0x10
    VM_PROT_TRUSTED = 0x20
    VM_PROT_IS_MASK = 0x40
    VM_PROT_STRIP_READ = 0x80


def to_vm_prot(flags: int):
    if not flags:
        return [VmProtection.VM_PROT_NONE]
    else:
        return [p for p in VmProtection if p.value & flags]


@dataclass
class KernelDataAbortSameElExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'Kernel_Data_Abort_Same_EL_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class Interrupt:
    ktraces: List
    pc: int
    is_user: bool
    type: int

    def __str__(self):
        return f'INTERRUPT, pc: {hex(self.pc)}, is_user: {self.is_user}, type: {InterruptType(self.type).name}'


@dataclass
class UserDataAbortLowerElExcArm:
    ktraces: List
    esr: int
    far: int
    pc: int

    def __str__(self):
        esr_class = self.esr >> 26
        try:
            esr_class = ExceptionSyndromeRegisterClass(esr_class).name
        except ValueError:
            pass
        return f'User_Data_Abort_Lower_EL_Exc_ARM, class: {esr_class}, far: {hex(self.far)}, pc: {hex(self.pc)}'


@dataclass
class DecrSet:
    ktraces: List
    decr: int
    deadline: int
    queue_count: int

    def __str__(self):
        return f'DecrSet, decr: {self.decr}'


@dataclass
class MachVmfault:
    ktraces: List
    addr: int
    is_kernel: bool
    result: int
    fault_type: DbgVmFaultType = None
    pid: int = None
    caller_prot: List = None

    def __str__(self):
        ret = f'MachVmfault, addr: {hex(self.addr)}, is_kernel: {self.is_kernel}, result: {self.result}'
        if self.result == 0:
            ret += f', type: {self.fault_type.name}'
            if self.pid is not None and self.caller_prot is not None:
                prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
                ret += f', vm_prot: {prot}, pid: {self.pid}'
        return ret


@dataclass
class RealFaultAddressInternal:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressInternal, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class RealFaultAddressExternal:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressExternal, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class RealFaultAddressSharedCache:
    ktraces: List
    vaddr: int
    user_tag: int
    caller_prot: List
    fault_type: DbgVmFaultType
    offset: int
    pid: int

    def __str__(self):
        prot = ' | '.join(map(lambda p: p.name, self.caller_prot))
        return (f'RealFaultAddressSharedCache, vaddr: {hex(self.vaddr)},'
                f' vm_prot: {prot}, type: {self.fault_type.name}, pid: {self.pid}')


@dataclass
class MachSched:
    ktraces: List
    reason: List[AsynchronousSystemTrapsReason]
    to: int
    from_sched_pri: int
    to_sched_pri: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_SCHED, to: {self.to}, reason: {reason}'


@dataclass
class MachStkhandoff:
    ktraces: List
    from_: int
    to: int
    reason: List[AsynchronousSystemTrapsReason]
    from_sched_pri: int
    to_sched_pri: int

    def __str__(self):
        return f'stack_handoff({self.from_}, {self.to})'


@dataclass
class MachMkrunnable:
    ktraces: List
    tid: int
    sched_pri: int
    wait_result: int
    runnable_threads: int

    def __str__(self):
        return f'MACH_MKRUNNABLE, tid: {self.tid}, wait_result: {self.wait_result}'


@dataclass
class MachIdle:
    ktraces: List
    from_: int
    process_state: ProcessState
    to: int
    reason: List

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_IDLE, from: {self.from_}, to: {self.to}, reason: {reason}, state: {self.process_state.name}'


@dataclass
class MachBlock:
    ktraces: List
    reason: List[AsynchronousSystemTrapsReason]
    continuation: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        return f'MACH_BLOCK, reason: {reason}, continuation: {hex(self.continuation)}'


@dataclass
class MachWait:
    ktraces: List
    event: int

    def __str__(self):
        return f'MACH_WAIT, event: {hex(self.event)}'


@dataclass
class MachDispatch:
    ktraces: List
    tid: int
    reason: List
    state: List
    runnable_threads: int

    def __str__(self):
        reason = ' | '.join(map(lambda r: r.name, self.reason))
        state = ' | '.join(map(lambda s: s.name, self.state))
        return f'MACH_DISPATCH, tid: {self.tid}, reason: {reason}, state: {state}'


@dataclass
class ThreadGroupSet:
    ktraces: List
    current_tgid: int
    target_tgid: int
    tid: int
    home_tgid: int

    def __str__(self):
        return (f'THREAD_GROUP_SET, from: {self.current_tgid}, to: {self.target_tgid}, '
                f'tid: {self.tid}, home: {self.home_tgid}')


@dataclass
class SchedClutchCpuThreadSelect:
    ktraces: List
    tid: int
    tgid: int
    scb_bucket: int

    def __str__(self):
        return f'SCHED_CLUTCH_CPU_THREAD_SELECT, tid: {self.tid}'


@dataclass
class SchedClutchTgBucketPri:
    ktraces: List
    tgid: int
    scb_bucket: int
    priority: int
    interactive_score: int

    def __str__(self):
        return f'SCHED_CLUTCH_TG_BUCKET_PRI, tgid: {self.tgid}, bucket: {self.scb_bucket}, priority: {self.priority}'


def handle_kernel_data_abort_same_el_exc_arm(parser, events):
    args = events[0].values
    return KernelDataAbortSameElExcArm(events, args[0], args[1], args[2])


def handle_user_svc64_exc_arm(parser, events):
    return parser.parse_event_list(events[1:-1]) if len(events) > 2 else None


def handle_user_data_abort_lower_el_exc_arm(parser, events):
    args = events[0].values
    return UserDataAbortLowerElExcArm(events, args[0], args[1], args[2])


def handle_interrupt(parser, events):
    args = events[0].values
    return Interrupt(events, args[1], bool(args[2]), args[3])


def handle_decr_set(parser, events):
    args = events[0].values
    return DecrSet(events, args[0], args[2], args[3])


def handle_mach_vmfault(parser, events):
    args = events[0].values
    is_kernel = bool(args[2])
    rets = events[-1].values
    result = rets[2]
    fault_type = None
    pid = None
    caller_prot = None
    if result == 0:
        fault_type = DbgVmFaultType(rets[3])
        real_events = [e for e in events[1:-1] if 0x1320008 <= e.eventid <= 0x1320014]
        if real_events:
            vm_fault_real = parser.parse_event_list(real_events)
            pid = vm_fault_real.pid
            caller_prot = vm_fault_real.caller_prot
    return MachVmfault(events, args[1], is_kernel, result, fault_type, pid, caller_prot)


def handle_real_fault_address(addr_type, parser, events):
    args = events[0].values
    caller_prot = to_vm_prot((args[1] >> 8) & 0xff)
    fault_type = DbgVmFaultType(args[1] & 0xff)
    return addr_type(events, args[0], args[1] >> 16, caller_prot, fault_type, args[2], args[3])


def handle_mach_sched(parser, events):
    args = events[0].values
    return MachSched(events, to_ast_reasons(args[0]), args[1], args[2], args[3])


def handle_mach_stkhandoff(parser, events):
    args = events[0].values
    return MachStkhandoff(events, events[0].tid, args[1], to_ast_reasons(args[0]), args[2], args[3])


def handle_mach_mkrunnable(parser, events):
    args = events[0].values
    return MachMkrunnable(events, args[0], args[1], args[2], args[3])


def handle_mach_idle(parser, events):
    args = events[-1].values
    return MachIdle(events, args[0], ProcessState(args[1]), args[2], to_ast_reasons(args[3]))


def handle_mach_block(parser, events):
    args = events[0].values
    return MachBlock(events, to_ast_reasons(args[0]), args[1])


def handle_mach_wait(parser, events):
    return MachWait(events, events[0].values[0])


def handle_mach_dispatch(parser, events):
    args = events[0].values
    return MachDispatch(events, args[0], to_ast_reasons(args[1]), to_thread_state(args[2]), args[3])


def handle_thread_group_set(parser, events):
    args = events[0].values
    return ThreadGroupSet(events, ctypes.c_int64(args[0]).value, args[1], args[2], args[3])


def handle_sched_clutch_cpu_thread_select(parser, events):
    args = events[0].values
    return SchedClutchCpuThreadSelect(events, args[0], args[1], args[2])


def handle_sched_clutch_tg_bucket_pri(parser, events):
    args = events[0].values
    return SchedClutchTgBucketPri(events, args[0], args[1], args[2], args[3])


handlers = {
    'Kernel_Data_Abort_Same_EL_Exc_ARM': handle_kernel_data_abort_same_el_exc_arm,
    'User_SVC64_Exc_ARM': handle_user_svc64_exc_arm,
    'User_Data_Abort_Lower_EL_Exc_ARM': handle_user_data_abort_lower_el_exc_arm,
    'INTERRUPT': handle_interrupt,
    'DecrSet': handle_decr_set,
    'MACH_vmfault': handle_mach_vmfault,
    'RealFaultAddressInternal': partial(handle_real_fault_address, RealFaultAddressInternal),
    'RealFaultAddressExternal': partial(handle_real_fault_address, RealFaultAddressExternal),
    'RealFaultAddressSharedCache': partial(handle_real_fault_address, RealFaultAddressSharedCache),
    'MACH_SCHED': handle_mach_sched,
    'MACH_STKHANDOFF': handle_mach_stkhandoff,
    'MACH_MKRUNNABLE': handle_mach_mkrunnable,
    'MACH_IDLE': handle_mach_idle,
    'MACH_BLOCK': handle_mach_block,
    'MACH_WAIT': handle_mach_wait,
    'MACH_DISPATCH': handle_mach_dispatch,
    'THREAD_GROUP_SET': handle_thread_group_set,
    'SCHED_CLUTCH_CPU_THREAD_SELECT': handle_sched_clutch_cpu_thread_select,
    'SCHED_CLUTCH_TG_BUCKET_PRI': handle_sched_clutch_tg_bucket_pri,
}

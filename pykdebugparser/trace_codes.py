import functools
from typing import FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple
from pathlib import Path


def from_trace_codes_text(codes_text: str) -> Mapping[int, str]:
    """
    Convert a trace codes text to dictionary.
    :param codes_text: Trace codes file data.
    :return: Mapping between code and event name.
    """
    return {int(s[0], 16): s[1] for s in map(lambda l: l.split(), codes_text.splitlines())}


def from_trace_codes_file(path: str) -> Mapping[int, str]:
    """
    Read trace codes from a file.
    :param path: Trace codes file path.
    :return: Mapping between code and event name.
    """
    with open(path, 'r') as fd:
        return from_trace_codes_text(fd.read())


def default_trace_codes() -> Mapping[int, str]:
    """
    Get the default trace codes mapping.
    :return: Mapping between code and event name.
    """
    with open(Path(__file__).resolve().parent.joinpath('trace.codes'), 'r') as fd:
        return from_trace_codes_text(fd.read())


def syscall_eventids(names: Iterable[str], trace_codes: Optional[Mapping[int, str]] = None) -> Set[int]:
    """
    Get the event ids of BSD syscalls by name, for `PyKdebugParser.filter_eventid`.
    A name also matches its `_nocancel` and `_dprotected_np` variants (e.g. `open` gives `BSC_open`,
    `BSC_open_nocancel` and `BSC_open_dprotected_np`, which opens with a data protection class).
    :param names: Syscall names, such as `open` or `openat`.
    :param trace_codes: Mapping between code and event name; the default trace codes if omitted.
    :return: The event ids.
    :raises ValueError: A name is not a known syscall.
    """
    codes = {name: code for code, name in (default_trace_codes() if trace_codes is None else trace_codes).items()}
    eventids = set()
    unknown = []
    for name in names:
        variants = (f'BSC_{name}', f'BSC_{name}_nocancel', f'BSC_{name}_dprotected_np')
        matches = {codes[event] for event in variants if event in codes}
        if not matches:
            unknown.append(name)
        eventids |= matches
    if unknown:
        raise ValueError(f'unknown syscalls: {", ".join(unknown)}')
    return eventids


def syscall_names(trace_codes: Optional[Mapping[int, str]] = None) -> List[str]:
    """
    Get the names `syscall_eventids` accepts. A `_nocancel` variant is left out, its base name covers it.
    :param trace_codes: Mapping between code and event name; the default trace codes if omitted.
    :return: The sorted syscall names.
    """
    codes = default_trace_codes() if trace_codes is None else trace_codes
    # `BSC_#123`-style names are placeholders for syscall numbers without a name.
    names = {name[len('BSC_'):] for name in codes.values() if name.startswith('BSC_') and '#' not in name}
    return sorted(name for name in names if not (name.endswith('_nocancel') and name[:-len('_nocancel')] in names))


def event_eventids(names: Iterable[str], trace_codes: Optional[Mapping[int, str]] = None) -> Set[int]:
    """
    Get the event ids of trace code names, for `PyKdebugParser.filter_eventid`. A name some codes share gives all of
    them.
    :param names: Trace code names, such as `DBG_DYLD_TIMING_DLOPEN`.
    :param trace_codes: Mapping between code and event name; the default trace codes if omitted.
    :return: The event ids.
    :raises ValueError: A name is not a known trace code name.
    """
    codes = {}
    for code, name in (default_trace_codes() if trace_codes is None else trace_codes).items():
        codes.setdefault(name, set()).add(code)
    names = list(names)
    unknown = [name for name in names if name not in codes]
    if unknown:
        raise ValueError(f'unknown events: {", ".join(unknown)}')
    return {code for name in names for code in codes[name]}


# Syscall groups of `parse-live`, by subsystem (each name also matches its _nocancel variant).
SYSCALL_GROUPS: Mapping[str, Tuple[str, ...]] = {
    # Syscalls that take a path.
    'fs': (
        'access',
        'access_extended',
        'chdir',
        'chmod',
        'chmod_extended',
        'chown',
        'chroot',
        'clonefileat',
        'exchangedata',
        'faccessat',
        'fchflagsat',
        'fchmodat',
        'fchownat',
        'fstatat',
        'fstatat64',
        'getattrlist',
        'getattrlistat',
        'getxattr',
        'guarded_open_dprotected_np',
        'guarded_open_np',
        'lchown',
        'link',
        'linkat',
        'listxattr',
        'lstat',
        'lstat64',
        'lstat64_extended',
        'lstat_extended',
        'mkdir',
        'mkdir_extended',
        'mkdirat',
        'mkfifo',
        'mkfifo_extended',
        'mkfifoat',
        'mknod',
        'mknodat',
        'mount',
        'open',
        'open_dprotected_np',
        'open_extended',
        'openat',
        'openat_dprotected_np',
        'openbyid_np',
        'pathconf',
        'readlink',
        'readlinkat',
        'removexattr',
        'rename',
        'renameat',
        'renameatx_np',
        'revoke',
        'rmdir',
        'searchfs',
        'setattrlist',
        'setattrlistat',
        'setxattr',
        'stat',
        'stat64',
        'stat64_extended',
        'stat_extended',
        'statfs',
        'statfs64',
        'symlink',
        'symlinkat',
        'truncate',
        'undelete',
        'unlink',
        'unlinkat',
        'unmount',
        'utimes',
    ),
    'net': (
        'accept',
        'bind',
        'connect',
        'connectx',
        'disconnectx',
        'getpeername',
        'getsockname',
        'getsockopt',
        'listen',
        'peeloff',
        'recvfrom',
        'recvmsg',
        'recvmsg_x',
        'sendfile',
        'sendmsg',
        'sendmsg_x',
        'sendto',
        'setsockopt',
        'shutdown',
        'socket',
        'socket_delegate',
        'socketpair',
    ),
    'proc': (
        'abort_with_payload',
        'execve',
        'exit',
        'fork',
        'kill',
        'pid_resume',
        'pid_suspend',
        'posix_spawn',
        'ptrace',
        'setpgid',
        'setsid',
        'terminate_with_payload',
        'vfork',
        'wait4',
        'waitid',
    ),
    # Syscalls on file descriptors: reads and writes, and the descriptors themselves.
    'io': (
        'fchflags',
        'fchmod',
        'fchown',
        'fdatasync',
        'fgetattrlist',
        'fgetxattr',
        'flistxattr',
        'fremovexattr',
        'fsetattrlist',
        'fsetxattr',
        'fstatfs',
        'fstatfs64',
        'fsync',
        'ftruncate',
        'futimes',
        'getattrlistbulk',
        'getdirentries64',
        'getdirentriesattr',
        'guarded_close_np',
        'guarded_pwrite_np',
        'guarded_write_np',
        'guarded_writev_np',
        'ioctl',
        'lseek',
        'pipe',
        'pipe2',
        'pread',
        'pwrite',
        'read',
        'readv',
        'sendfile',
        'sys_close',
        'sys_dup',
        'sys_dup2',
        'sys_dup3',
        'sys_fcntl',
        'sys_fileport_makefd',
        'sys_fileport_makeport',
        'sys_flock',
        'sys_fstat64',
        'sys_preadv',
        'sys_pwritev',
        'write',
        'writev',
    ),
    # Memory mappings and their protections.
    'mem': (
        'madvise',
        'map_with_linking_np',
        'mincore',
        'minherit',
        'mlock',
        'mlockall',
        'mmap',
        'mprotect',
        'mremap_encrypted',
        'msync',
        'munlock',
        'munlockall',
        'munmap',
        'shared_region_check_np',
        'shared_region_map_and_slide_2_np',
        'shared_region_map_and_slide_np',
    ),
    # Sending, handling and masking signals.
    'signal': (
        'disable_threadsignal',
        'kill',
        'pthread_kill',
        'pthread_sigmask',
        'sigaction',
        'sigaltstack',
        'sigpending',
        'sigprocmask',
        'sigreturn',
        'sigsuspend',
        'sigwait',
    ),
    # Credentials, code signing and policy (Sandbox, AMFI) checks, and access to other tasks.
    'cred': (
        'audit_session_port',
        'csops',
        'csops_audittoken',
        'csrctl',
        'initgroups',
        'issetugid',
        'mac_syscall',
        'persona',
        'setauid',
        'setegid',
        'seteuid',
        'setgid',
        'setgroups',
        'setlogin',
        'setregid',
        'setreuid',
        'setuid',
        'task_inspect_for_pid',
        'task_read_for_pid',
    ),
    # Waiting and waking: locks, condition variables, kqueues and workqueues.
    'sync': (
        'kevent',
        'kevent64',
        'kevent_id',
        'kevent_qos',
        'kqueue',
        'kqueue_workloop_ctl',
        'poll',
        'pselect',
        'psynch_cvbroad',
        'psynch_cvclrprepost',
        'psynch_cvsignal',
        'psynch_cvwait',
        'psynch_mutexdrop',
        'psynch_mutexwait',
        'select',
        'sem_close',
        'sem_open',
        'sem_post',
        'sem_trywait',
        'sem_unlink',
        'sem_wait',
        'semwait_signal',
        'ulock_wait',
        'ulock_wait2',
        'ulock_wake',
        'workq_kernreturn',
    ),
    # Mach traps only (`group_mach_traps`).
    'mach': (),
}
# The Mach traps of a syscall group, by trace code name (they are events, as `--event` takes them), the kernel traces
# them in their own subclass. The `mach` group is every Mach trap pykdebugparser parses (`group_mach_traps`).
MACH_TRAP_GROUPS: Mapping[str, Tuple[str, ...]] = {
    'mem': (
        'MSC_kern_mach_vm_purgable_control_trap',
        'MSC_mach_vm_allocate_trap',
        'MSC_mach_vm_deallocate_trap',
        'MSC_mach_vm_map_trap',
        'MSC_mach_vm_protect_trap',
    ),
    'cred': (
        'MSC_pid_for_task',
        'MSC_task_for_pid',
        'MSC_task_name_for_pid',
    ),
    'sync': (
        'MSC_mach_wait_until',
        'MSC_semaphore_signal_trap',
        'MSC_semaphore_timedwait_trap',
        'MSC_semaphore_wait_trap',
    ),
}


@functools.lru_cache(maxsize=None)
def parsed_events() -> FrozenSet[str]:
    """
    Get the trace code names of the events pykdebugparser parses (the others are only printed when selected by id).
    :return: The names.
    """
    # Imported here, the trace handlers import this module.
    from pykdebugparser.traces_parser import TracesParser

    return frozenset(TracesParser(default_trace_codes(), {}, {}).handlers)


@functools.lru_cache(maxsize=None)
def _parsed_mach_traps() -> Tuple[str, ...]:
    """The trace code names of the Mach traps pykdebugparser parses."""
    parsed = parsed_events()
    return tuple(sorted({name for name in default_trace_codes().values() if name.startswith('MSC_') and name in parsed}))


def group_mach_traps(group: str) -> Tuple[str, ...]:
    """
    Get the Mach traps of a syscall group (see `SYSCALL_GROUPS`).
    :param group: Group name, such as `mem`.
    :return: The trace code names of its Mach traps, for `event_eventids`.
    """
    return _parsed_mach_traps() if group == 'mach' else MACH_TRAP_GROUPS.get(group, ())


# The user space event groups of `parse-live` (`--xpc`, ...), by the prefix of their trace code names. Their events have
# no decoder, so they print as their name and raw arguments.
EVENT_GROUP_PREFIXES: Mapping[str, str] = {'xpc': 'XPC_', 'dispatch': 'DISPATCH_', 'runloop': 'CFRL_'}


def group_events(group: str) -> Tuple[str, ...]:
    """
    Get the events of a user space event group (see `EVENT_GROUP_PREFIXES`).
    :param group: Group name, such as `xpc`.
    :return: The sorted trace code names of its events, for `event_eventids`.
    """
    prefix = EVENT_GROUP_PREFIXES[group]
    return tuple(sorted({name for name in default_trace_codes().values() if name.startswith(prefix)}))

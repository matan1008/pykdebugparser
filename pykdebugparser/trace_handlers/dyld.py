from dataclasses import dataclass
from enum import Enum
from typing import List
from uuid import UUID


class RtldFlag(Enum):
    RTLD_LAZY = 0x1
    RTLD_NOW = 0x2
    RTLD_LOCAL = 0x4
    RTLD_GLOBAL = 0x8
    RTLD_NOLOAD = 0x10
    RTLD_NODELETE = 0x80
    RTLD_FIRST = 0x100


def to_rtld_flags(flags: int):
    return [r for r in RtldFlag if r.value & flags]


def _image(path: str) -> str:
    return f', image: "{path}"' if path else ''


@dataclass
class DyldUuidMapA:
    ktraces: List
    uuid: UUID
    load_addr: int
    fsid: int

    def __str__(self):
        return f'DYLD_uuid_map_a, uuid: "{self.uuid}", load_addr: {hex(self.load_addr)}, fsid: {hex(self.fsid)}'


@dataclass
class DyldUuidMapB:
    ktraces: List
    fid_objno: int
    fid_generation: int
    path: str = ''

    def __str__(self):
        rep = f'DYLD_uuid_map_b, fid_objno: {self.fid_objno}, fid_generation: {hex(self.fid_generation)}'
        return rep + f', path: "{self.path}"' if self.path else rep


@dataclass
class DyldUuidUnmapA:
    ktraces: List
    uuid: UUID
    load_addr: int
    fsid: int

    def __str__(self):
        return f'DYLD_uuid_unmap_a, uuid: "{self.uuid}", load_addr: {hex(self.load_addr)}, fsid: {hex(self.fsid)}'


@dataclass
class DyldUuidUnmapB:
    ktraces: List
    fid_objno: int
    fid_generation: int
    path: str = ''

    def __str__(self):
        rep = f'DYLD_uuid_unmap_b, fid_objno: {self.fid_objno}, fid_generation: {hex(self.fid_generation)}'
        return rep + f', path: "{self.path}"' if self.path else rep


@dataclass
class DyldUuidSharedCacheA:
    ktraces: List
    uuid: UUID
    load_addr: int
    fsid: int

    def __str__(self):
        return (f'DYLD_uuid_shared_cache_a, uuid: "{self.uuid}", load_addr: {hex(self.load_addr)}, '
                f'fsid: {hex(self.fsid)}')


@dataclass
class DyldUuidSharedCacheB:
    ktraces: List
    fid_objno: int
    fid_generation: int
    path: str = ''

    def __str__(self):
        rep = f'DYLD_uuid_shared_cache_b, fid_objno: {self.fid_objno}, fid_generation: {hex(self.fid_generation)}'
        return rep + f', path: "{self.path}"' if self.path else rep


@dataclass
class DyldLaunchExecutable:
    ktraces: List
    main_executable_mh: int
    uuid_map_a: List

    def __str__(self):
        return f'DBG_DYLD_TIMING_LAUNCH_EXECUTABLE, main_executable_mh: {hex(self.main_executable_mh)}'


@dataclass
class DyldMapImage:
    ktraces: List
    path: str

    def __str__(self):
        return f'DBG_DYLD_TIMING_MAP_IMAGE, path: {self.path}'


@dataclass
class DyldFuncForAddImage:
    ktraces: List
    addr: int
    func: int
    image: str = ''

    def __str__(self):
        return f'DBG_DYLD_TIMING_FUNC_FOR_ADD_IMAGE, addr: {hex(self.addr)}{_image(self.image)}, func: {hex(self.func)}'


@dataclass
class DyldFuncForRemoveImage:
    ktraces: List
    addr: int
    func: int
    image: str = ''

    def __str__(self):
        return (f'DBG_DYLD_TIMING_FUNC_FOR_REMOVE_IMAGE, addr: {hex(self.addr)}{_image(self.image)}, '
                f'func: {hex(self.func)}')


@dataclass
class DyldStaticInitializer:
    ktraces: List
    mh: int
    func: int
    image: str = ''

    def __str__(self):
        return f'DBG_DYLD_TIMING_STATIC_INITIALIZER, mh: {hex(self.mh)}{_image(self.image)}, func: {hex(self.func)}'


@dataclass
class DyldObjcInit:
    ktraces: List
    mh: int
    image: str = ''

    def __str__(self):
        return f'DBG_DYLD_TIMING_OBJC_INIT, mh: {hex(self.mh)}{_image(self.image)}'


@dataclass
class DyldTiming:
    """A dyld phase traced without arguments (applying fixups, mapping ObjC images, ...)."""
    ktraces: List
    name: str

    def __str__(self):
        return self.name


@dataclass
class DyldBootstrapStart:
    ktraces: List

    def __str__(self):
        return 'DBG_DYLD_TIMING_BOOTSTRAP_START'


@dataclass
class Dlopen:
    ktraces: List
    path: str
    flags: List
    handle: int

    def __str__(self):
        flags = ' | '.join(map(lambda f: f.name, self.flags))
        return f'dlopen("{self.path}", {flags}), handle: {hex(self.handle)}'


@dataclass
class DlopenPreflight:
    ktraces: List
    path: str
    compatible: bool

    def __str__(self):
        return f'dlopen_preflight("{self.path}"), compatible: {self.compatible}'


@dataclass
class Dlclose:
    ktraces: List
    handle: int

    def __str__(self):
        return f'dlclose({hex(self.handle)})'


@dataclass
class Dlsym:
    ktraces: List
    handle: int
    symbol: str
    address: int

    def __str__(self):
        return f'dlsym({hex(self.handle)}, "{self.symbol}"), address: {hex(self.address)}'


@dataclass
class Dladdr:
    ktraces: List
    addr: int
    ret: int

    def __str__(self):
        return f'dladdr({hex(self.addr)}), ret: {self.ret}'


# dyld traces each image (un)load as an `_a` event with its UUID and load address, followed on the same thread by a
# `_b` event with the id of its path string. The parser keeps the loaded images per process, so the events that only
# carry a mach header (initializers, ObjC init, ...) can name their image.

def _image_path(parser, events, mh):
    return parser.dyld_images.get((parser.threads_pids.get(events[0].tid, -1), mh), '')


def _map_a(parser, events, cls):
    args = events[0].values
    parser.dyld_pending_load_addr[events[0].tid] = args[2]
    return cls(events, UUID(bytes=events[0].data[:16]), args[2], args[3])


def _map_b(parser, events, cls, loaded):
    args = events[0].values
    path = parser.global_strings.get(args[1], '') if args[1] else ''
    load_addr = parser.dyld_pending_load_addr.pop(events[0].tid, None)
    if load_addr is not None:
        key = (parser.threads_pids.get(events[0].tid, -1), load_addr)
        if loaded and path:
            parser.dyld_images[key] = path
        elif not loaded:
            parser.dyld_images.pop(key, None)
    return cls(events, args[0] & 0xffffffff, args[0] >> 32, path)


def handle_uuid_map_a(parser, events):
    return _map_a(parser, events, DyldUuidMapA)


def handle_uuid_map_b(parser, events):
    return _map_b(parser, events, DyldUuidMapB, loaded=True)


def handle_uuid_unmap_a(parser, events):
    return _map_a(parser, events, DyldUuidUnmapA)


def handle_uuid_unmap_b(parser, events):
    return _map_b(parser, events, DyldUuidUnmapB, loaded=False)


def handle_uuid_shared_cache_a(parser, events):
    return _map_a(parser, events, DyldUuidSharedCacheA)


def handle_uuid_shared_cache_b(parser, events):
    return _map_b(parser, events, DyldUuidSharedCacheB, loaded=True)


def handle_timing_launch_executable(parser, events):
    map_a = [handle_uuid_map_a(parser, [e]) for e in events if parser.trace_codes.get(e.eventid) == 'DYLD_uuid_map_a']
    map_a += [handle_uuid_shared_cache_a(parser, [e]) for e in events if
              parser.trace_codes.get(e.eventid) == 'DYLD_uuid_shared_cache_a']
    map_a = sorted(map_a, key=lambda x: x.load_addr)
    return DyldLaunchExecutable(events, events[0].values[1], map_a)


def handle_timing_map_image(parser, events):
    args = events[0].values
    path = parser.global_strings[args[1]] if args[1] else ''
    return DyldMapImage(events, path)


def handle_timing_func_for_add_image(parser, events):
    args = events[0].values
    return DyldFuncForAddImage(events, args[1], args[2], _image_path(parser, events, args[1]))


def handle_timing_func_for_remove_image(parser, events):
    args = events[0].values
    return DyldFuncForRemoveImage(events, args[1], args[2], _image_path(parser, events, args[1]))


def handle_timing_static_initializer(parser, events):
    args = events[0].values
    return DyldStaticInitializer(events, args[1], args[2], _image_path(parser, events, args[1]))


def handle_timing_objc_init(parser, events):
    args = events[0].values
    return DyldObjcInit(events, args[1], _image_path(parser, events, args[1]))


def handle_timing(parser, events):
    return DyldTiming(events, parser.trace_codes[events[0].eventid])


def handle_timing_bootstrap_start(parser, events):
    return DyldBootstrapStart(events)


def handle_timing_dlopen(parser, events):
    args = events[0].values
    path = parser.global_strings[args[1]] if args[1] else ''
    return Dlopen(events, path, to_rtld_flags(args[2]), events[-1].values[1])


def handle_timing_dlopen_preflight(parser, events):
    return DlopenPreflight(events, parser.global_strings[events[0].values[1]], bool(events[-1].values[1]))


def handle_timing_dlclose(parser, events):
    return Dlclose(events, events[0].values[1])


def handle_timing_dlsym(parser, events):
    args = events[0].values
    return Dlsym(events, args[1], parser.global_strings[args[2]], events[-1].values[1])


def handle_timing_dladdr(parser, events):
    return Dladdr(events, events[0].values[1], events[-1].values[1])


handlers = {
    'DYLD_uuid_map_a': handle_uuid_map_a,
    'DYLD_uuid_map_b': handle_uuid_map_b,
    'DYLD_uuid_unmap_a': handle_uuid_unmap_a,
    'DYLD_uuid_unmap_b': handle_uuid_unmap_b,
    'DYLD_uuid_shared_cache_a': handle_uuid_shared_cache_a,
    'DYLD_uuid_shared_cache_b': handle_uuid_shared_cache_b,
    'DBG_DYLD_TIMING_LAUNCH_EXECUTABLE': handle_timing_launch_executable,
    'DBG_DYLD_TIMING_MAP_IMAGE': handle_timing_map_image,
    'DBG_DYLD_TIMING_FUNC_FOR_ADD_IMAGE': handle_timing_func_for_add_image,
    'DBG_DYLD_TIMING_FUNC_FOR_REMOVE_IMAGE': handle_timing_func_for_remove_image,
    'DBG_DYLD_TIMING_STATIC_INITIALIZER': handle_timing_static_initializer,
    'DBG_DYLD_TIMING_OBJC_INIT': handle_timing_objc_init,
    'DBG_DYLD_TIMING_OBJC_MAP': handle_timing,
    'DBG_DYLD_TIMING_APPLY_FIXUPS': handle_timing,
    'DBG_DYLD_TIMING_ATTACH_CODESIGNATURE': handle_timing,
    'DBG_DYLD_TIMING_BUILD_CLOSURE': handle_timing,
    'DBG_DYLD_REMOTE_IMAGE_NOTIFIER': handle_timing,
    'DBG_DYLD_TIMING_BOOTSTRAP_START': handle_timing_bootstrap_start,
    'DBG_DYLD_TIMING_DLOPEN': handle_timing_dlopen,
    'DBG_DYLD_TIMING_DLOPEN_PREFLIGHT': handle_timing_dlopen_preflight,
    'DBG_DYLD_TIMING_DLCLOSE': handle_timing_dlclose,
    'DBG_DYLD_TIMING_DLSYM': handle_timing_dlsym,
    'DBG_DYLD_TIMING_DLADDR': handle_timing_dladdr,
}

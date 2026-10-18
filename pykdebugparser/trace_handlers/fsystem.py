from dataclasses import dataclass
from typing import List, Optional

from pykdebugparser.trace_codes import default_trace_codes

DBG_DKRW = 0x302
# bsd/sys/kdebug.h: the code of a disk I/O event is these flags (`P_RdMetaAsync`, `P_WrDataDone`, ...).
DKIO_DONE = 0x01


@dataclass
class VfsLookup:
    ktraces: List
    path: str
    vnode_id: int

    def __str__(self):
        return f'lookup("{self.path}"), vnode id: {self.vnode_id}'


@dataclass
class DiskIo:
    """A disk I/O, from its issue (device, block, size) to its completion (bytes not transferred, error)."""
    ktraces: List
    name: str
    dev: Optional[int]
    blkno: Optional[int]
    size: Optional[int]
    resid: int
    error: int

    def __str__(self):
        rep = self.name
        if self.dev is not None:
            rep += f', dev: {self.dev >> 24},{self.dev & 0xffffff}, blkno: {hex(self.blkno)}, size: {self.size}'
        return rep + f', resid: {self.resid}, error: {self.error}'


def handle_vfs_lookup(parser, events):
    node = parser.parse_vnode(events)
    return VfsLookup(events, node.path, node.vnode_id)


def handle_disk_io(parser, events):
    # xnu traces the issue as (buf, dev, blkno, size) and the completion, often on another thread, as
    # (buf, vnode, resid, error); the buf address pairs them. Print one line when the I/O completes.
    event = events[0]
    buf = event.values[0]
    if not (event.eventid >> 2) & DKIO_DONE:
        parser.pending_disk_io[buf] = event
        return None
    start = parser.pending_disk_io.pop(buf, None)
    resid, error = event.values[2], event.values[3]
    if start is None:
        return DiskIo(events, parser.trace_codes[event.eventid].removesuffix('Done'), None, None, None, resid, error)
    args = start.values
    return DiskIo([start, event], parser.trace_codes[start.eventid], args[1] & 0xffffffff, args[2], args[3], resid,
                  error)


handlers = {
    'VFS_LOOKUP': handle_vfs_lookup,
}
handlers.update({name: handle_disk_io for eventid, name in default_trace_codes().items() if eventid >> 16 == DBG_DKRW})

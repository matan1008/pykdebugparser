from collections import namedtuple
from dataclasses import dataclass
from typing import List

from pykdebugparser.kevent import DgbFuncQual
from pykdebugparser.kd_buf_parser import ProcessData
from pykdebugparser.trace_handlers.bsd import handlers as bsd_handlers
from pykdebugparser.trace_handlers.fsystem import handlers as fsystem_handlers
from pykdebugparser.trace_handlers.mach import handlers as mach_handlers

Vnode = namedtuple('Vnode', ['ktraces', 'vnode_id', 'path'])


@dataclass
class MachStackHandoff:
    ktraces: List

    def __str__(self):
        return 'stack_handoff()'


@dataclass
class TraceDataNewthread:
    ktraces: List
    tid: int
    pid: int
    is_exec_copy: int
    uniqueid: int

    def __str__(self):
        return f'New thread {self.tid} of parent: {self.pid}'


@dataclass
class TraceStringNewthread:
    ktraces: List
    name: List

    def __str__(self):
        return f'New thread of parent: {self.name}'


@dataclass
class TraceDataExec:
    ktraces: List
    pid: int
    fsid: int
    fileid: int

    def __str__(self):
        return f'New process pid: {self.pid}'


@dataclass
class TraceStringExec:
    ktraces: List
    name: List

    def __str__(self):
        return f'New process name: {self.name}'


class TracesParser:
    def __init__(self, trace_codes_map, thread_map):
        self.trace_codes = trace_codes_map
        self.on_going_events = {}
        self.thread_map = thread_map
        self.qualifiers_actions = {
            DgbFuncQual.DBG_FUNC_START.value: self._feed_start_event,
            DgbFuncQual.DBG_FUNC_END.value: self._feed_end_event,
            DgbFuncQual.DBG_FUNC_ALL.value: self._feed_single_event,
            DgbFuncQual.DBG_FUNC_NONE.value: self._feed_single_event,
        }
        self.trace_handlers = {
            'TRACE_DATA_NEWTHREAD': self.handle_trace_data_newthread,
            'TRACE_DATA_EXEC': self.handle_trace_data_exec,
            'TRACE_STRING_NEWTHREAD': self.handle_trace_string_newthread,
            'TRACE_STRING_EXEC': self.handle_trace_string_exec,
        }
        self.last_data_newthread = None
        self.last_data_exec = None
        self.handlers = {}
        self.handlers.update(bsd_handlers)
        self.handlers.update(fsystem_handlers)
        self.handlers.update(mach_handlers)

    def feed(self, event):
        if event.eventid in self.trace_codes:
            trace_name = self.trace_codes[event.eventid]
            if trace_name in self.trace_handlers:
                self.trace_handlers[trace_name]([event])
                return

        return self.qualifiers_actions[event.func_qualifier](event)

    def feed_generator(self, generator):
        for event in generator:
            ret = self.feed(event)
            if ret is not None:
                yield ret

    def parse_event_list(self, events):
        if events[0].eventid not in self.trace_codes:
            return None
        trace_name = self.trace_codes[events[0].eventid]
        if trace_name not in self.handlers:
            return None
        return self.handlers[trace_name](self, events)

    @staticmethod
    def vnode_generator(events):
        path = b''
        vnodeid = 0
        lookup_events = []
        for event in events:
            lookup_events.append(event)
            if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
                vnodeid = event.values[0]
                path += event.data[8:]
            else:
                path += event.data

            if event.func_qualifier & DgbFuncQual.DBG_FUNC_END.value:
                yield Vnode(lookup_events, vnodeid, path.replace(b'\x00', b'').decode())
                path = b''
                vnodeid = 0
                lookup_events = []

    def parse_vnode(self, events):
        try:
            return self.parse_vnodes(events)[0]
        except IndexError:
            return Vnode([], 0, '')

    def parse_vnodes(self, events):
        return list(self.vnode_generator([e for e in events if self.trace_codes.get(e.eventid) == 'VFS_LOOKUP']))

    def handle_mach_stkhandoff(self, events):
        return MachStackHandoff(events)

    def handle_trace_data_newthread(self, events):
        result = events[0].values
        self.last_data_newthread = TraceDataNewthread(events, result[0], result[1], result[2], result[3])
        return self.last_data_newthread

    def handle_trace_string_newthread(self, events):
        event = TraceStringNewthread(events, events[0].data.replace(b'\x00', b'').decode())
        self.thread_map[self.last_data_newthread.tid] = ProcessData(self.last_data_newthread.pid, event.name)
        return event

    def handle_trace_data_exec(self, events):
        result = events[0].values
        self.last_data_exec = TraceDataExec(events, result[0], result[1], result[2])
        return self.last_data_exec

    def handle_trace_string_exec(self, events):
        event = TraceStringExec(events, events[0].data.replace(b'\x00', b'').decode())
        self.thread_map[events[0].tid] = ProcessData(self.last_data_exec.pid, event.name)
        return event

    def _feed_start_event(self, event):
        if event.tid not in self.on_going_events:
            self.on_going_events[event.tid] = [event]
        else:
            self.on_going_events[event.tid].append(event)

    def _feed_end_event(self, event):
        if event.tid not in self.on_going_events:
            # Event end without start.
            return
        if event.eventid != self.on_going_events[event.tid][0].eventid:
            self.on_going_events[event.tid].append(event)
            return
        events = self.on_going_events.pop(event.tid)
        events.append(event)
        return self.parse_event_list(events)

    def _feed_single_event(self, event):
        if event.tid in self.on_going_events:
            self.on_going_events[event.tid].append(event)
        else:
            return self.parse_event_list([event])

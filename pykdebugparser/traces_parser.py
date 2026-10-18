from collections import namedtuple
from dataclasses import dataclass
from typing import List

from pykdebugparser.kevent import DgbFuncQual
from pykdebugparser.trace_handlers.bsd import handlers as bsd_handlers
from pykdebugparser.trace_handlers.dyld import handlers as dyld_handlers
from pykdebugparser.trace_handlers.fsystem import handlers as fsystem_handlers
from pykdebugparser.trace_handlers.mach import handlers as mach_handlers
from pykdebugparser.trace_handlers.perf import handlers as perf_handlers
from pykdebugparser.trace_handlers.trace import handlers as trace_handlers
from pykdebugparser.trace_handlers.turnstile import handlers as turnstile_handlers

Vnode = namedtuple('Vnode', ['ktraces', 'vnode_id', 'path'])


@dataclass
class RawTrace:
    """
    An event without a handler, shown by its trace code name and raw values.
    """
    ktraces: List
    name: str

    def __str__(self):
        rep = f'{self.name}({", ".join(map(hex, self.ktraces[0].values))})'
        if len(self.ktraces) > 1:
            rep += f', end: ({", ".join(map(hex, self.ktraces[-1].values))})'
        return rep


NO_RETURN_CALLS = ('BSC_exit', 'BSC_bsdthread_terminate')


class TracesParser:
    def __init__(self, trace_codes_map, threads_pids, pids_names):
        self.trace_codes = trace_codes_map
        self.on_going_events = {}
        self.on_going_traces = {}
        self.global_strings = {}
        self.threads_pids = threads_pids
        self.pids_names = pids_names
        self.tids_names = {}
        self.qualifiers_actions = {
            DgbFuncQual.DBG_FUNC_START.value: self._feed_start_event,
            DgbFuncQual.DBG_FUNC_END.value: self._feed_end_event,
            DgbFuncQual.DBG_FUNC_ALL.value: self._feed_single_event,
            DgbFuncQual.DBG_FUNC_NONE.value: self._feed_single_event,
        }
        self.last_data_newthread = None
        self.last_data_exec = None
        # Calls that never return, parsed from their start event.
        self.no_return_eventids = {eventid for eventid, name in trace_codes_map.items() if name in NO_RETURN_CALLS}
        # Disk I/Os issued and not completed yet, by their buf address.
        self.pending_disk_io = {}
        # Images dyld loaded, by (pid, load address), and the load address of each thread's last `DYLD_uuid_*_a` event.
        self.dyld_images = {}
        self.dyld_pending_load_addr = {}
        # Event ids to show as `RawTrace` when they have no handler.
        self.raw_eventids = set()
        self.handlers = {}
        self.handlers.update(bsd_handlers)
        self.handlers.update(dyld_handlers)
        self.handlers.update(fsystem_handlers)
        self.handlers.update(mach_handlers)
        self.handlers.update(perf_handlers)
        self.handlers.update(trace_handlers)
        self.handlers.update(turnstile_handlers)

    def feed(self, event):
        trace_name = self.trace_codes.get(event.eventid)
        if trace_name is not None and trace_name in trace_handlers:
            return self.qualifiers_actions[event.func_qualifier](event, self.on_going_traces)

        return self.qualifiers_actions[event.func_qualifier](event, self.on_going_events)

    def feed_generator(self, generator):
        feed = self.feed
        for event in generator:
            ret = feed(event)
            if ret is not None:
                yield ret

    def parse_event_list(self, events):
        trace_name = self.trace_codes.get(events[0].eventid)
        if trace_name is None:
            return None
        handler = self.handlers.get(trace_name)
        if handler is None:
            return RawTrace(events, trace_name) if events[0].eventid in self.raw_eventids else None
        return handler(self, events)

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

    def _feed_start_event(self, event, state):
        if event.eventid in self.no_return_eventids:
            # The thread or process ends inside the call, so its end is never traced.
            return self._feed_single_event(event, state)
        tid_state = state.get(event.tid)
        if tid_state is None:
            # New tid
            tid_state = state[event.tid] = {}

        tid_state[event.eventid] = []
        for events in tid_state.values():
            events.append(event)

    def _feed_end_event(self, event, state):
        tid_state = state.get(event.tid)
        if tid_state is None or event.eventid not in tid_state:
            # Event end without start.
            return

        for events in tid_state.values():
            events.append(event)

        events = tid_state.pop(event.eventid)
        return self.parse_event_list(events)

    def _feed_single_event(self, event, state):
        tid_state = state.get(event.tid)
        if tid_state:
            for events in tid_state.values():
                events.append(event)
        return self.parse_event_list([event])

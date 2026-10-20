from collections import OrderedDict, namedtuple
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
# Most events a live trace keeps for a call that didn't end yet. Nearly every call ends with a few dozens.
MAX_ONGOING_EVENTS = 4096
# Most strings a live trace keeps after they were released, events keep naming them for a short while.
MAX_RELEASED_STRINGS = 1024


class TracesParser:
    """
    :param live: Parse a live trace, keeping the memory of ongoing calls (the calls that didn't end yet) flat however
        long it runs. A call that keeps `MAX_ONGOING_EVENTS` events is forgotten, it most likely won't end (such as
        a run loop run). So is a call ongoing since before the gap before the last one when the kernel dropped
        events: its end was most likely among them. A forgotten call isn't parsed when it ends. The strings and
        images dyld named are forgotten when their process exits (or execs), strings soon after they are released, and
        threads when they terminate.
    """

    def __init__(self, trace_codes_map, threads_pids, pids_names, live=False):
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
        # Images dyld loaded, by pid and load address, and the load address of each thread's last `DYLD_uuid_*_a` event.
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
        self.live = live
        # The timestamp of the last gap of dropped events.
        self._last_gap = None
        if live:
            # Separate methods, so other traces pay nothing for it.
            self.qualifiers_actions.update({
                DgbFuncQual.DBG_FUNC_START.value: self._feed_start_event_live,
                DgbFuncQual.DBG_FUNC_END.value: self._feed_end_event_live,
                DgbFuncQual.DBG_FUNC_ALL.value: self._feed_single_event_live,
                DgbFuncQual.DBG_FUNC_NONE.value: self._feed_single_event_live,
            })
            self.handlers['TRACE_LOST_EVENTS'] = self._handle_lost_events_live
            self.handlers['TRACE_STRING_GLOBAL'] = self._handle_string_global_live
            self.handlers['TRACE_STRING_PROC_EXIT'] = self._handle_proc_exit_live
            self.handlers['TRACE_DATA_THREAD_TERMINATE'] = self._handle_thread_terminate_live
        # The strings each process named, the process of each string, and the strings released, oldest first.
        self._process_strings = {}
        self._string_processes = {}
        self._released_strings = OrderedDict()

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

    def _append_live(self, tid_state, event):
        full = False
        for events in tid_state.values():
            events.append(event)
            if len(events) >= MAX_ONGOING_EVENTS:
                full = True
        if full:
            for eventid in [eventid for eventid, events in tid_state.items() if len(events) >= MAX_ONGOING_EVENTS]:
                del tid_state[eventid]

    def _feed_start_event_live(self, event, state):
        if event.eventid in self.no_return_eventids:
            return self._feed_single_event_live(event, state)
        tid_state = state.get(event.tid)
        if tid_state is None:
            tid_state = state[event.tid] = {}
        tid_state[event.eventid] = []
        self._append_live(tid_state, event)

    def _feed_end_event_live(self, event, state):
        tid_state = state.get(event.tid)
        if tid_state is None or event.eventid not in tid_state:
            return
        events = tid_state.pop(event.eventid)
        events.append(event)
        self._append_live(tid_state, event)
        return self.parse_event_list(events)

    def _feed_single_event_live(self, event, state):
        tid_state = state.get(event.tid)
        if tid_state:
            self._append_live(tid_state, event)
        return self.parse_event_list([event])

    def _handle_lost_events_live(self, parser, events):
        previous_gap, self._last_gap = self._last_gap, events[0].timestamp
        if previous_gap is not None:
            for state in (self.on_going_events, self.on_going_traces):
                for tid in list(state):
                    tid_state = state[tid]
                    for eventid in [eventid for eventid, events in tid_state.items()
                                    if events[0].timestamp < previous_gap]:
                        del tid_state[eventid]
                    if not tid_state:
                        del state[tid]
        return trace_handlers['TRACE_LOST_EVENTS'](parser, events)

    def _forget_string(self, str_id):
        self.global_strings.pop(str_id, None)
        self._released_strings.pop(str_id, None)
        pid = self._string_processes.pop(str_id, None)
        strings = self._process_strings.get(pid)
        if strings is not None:
            strings.discard(str_id)

    def _handle_string_global_live(self, parser, events):
        trace = trace_handlers['TRACE_STRING_GLOBAL'](parser, events)
        str_id = trace.str_id
        if trace.vstr:
            self._released_strings.pop(str_id, None)
            pid = self.threads_pids.get(events[0].tid)
            previous_pid = self._string_processes.get(str_id, pid)
            if previous_pid != pid:
                self._process_strings[previous_pid].discard(str_id)
            self._string_processes[str_id] = pid
            self._process_strings.setdefault(pid, set()).add(str_id)
        elif str_id in self.global_strings:
            released = self._released_strings
            released[str_id] = None
            released.move_to_end(str_id)
            if len(released) > MAX_RELEASED_STRINGS:
                self._forget_string(next(iter(released)))
        return trace

    def _handle_proc_exit_live(self, parser, events):
        # An exec ends the process image too, and the new image names its own strings and images.
        pid = self.threads_pids.get(events[0].tid)
        for str_id in list(self._process_strings.pop(pid, ())):
            self._forget_string(str_id)
        self.dyld_images.pop(pid, None)
        return trace_handlers['TRACE_STRING_PROC_EXIT'](parser, events)

    def _handle_thread_terminate_live(self, parser, events):
        trace = trace_handlers['TRACE_DATA_THREAD_TERMINATE'](parser, events)
        # The kernel traces it once the thread is gone, nothing names it anymore.
        self.threads_pids.pop(trace.tid, None)
        self.tids_names.pop(trace.tid, None)
        self.dyld_pending_load_addr.pop(trace.tid, None)
        return trace

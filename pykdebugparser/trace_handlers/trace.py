from dataclasses import dataclass
from typing import List

from pykdebugparser.kevent import DgbFuncQual


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
class TraceDataExec:
    ktraces: List
    pid: int
    fsid: int
    fileid: int

    def __str__(self):
        return f'New process pid: {self.pid}'


@dataclass
class TraceStringGlobal:
    ktraces: List
    debugid: int
    str_id: int
    vstr: str

    def __str__(self):
        return f'New global string: "{self.vstr}", id: {self.str_id}'


@dataclass
class TraceStringNewthread:
    ktraces: List
    name: List

    def __str__(self):
        return f'New thread of parent: {self.name}'


@dataclass
class TraceStringExec:
    ktraces: List
    name: List

    def __str__(self):
        return f'New process name: {self.name}'


def handle_trace_data_newthread(parser, events):
    result = events[0].values
    parser.last_data_newthread = TraceDataNewthread(events, result[0], result[1], result[2], result[3])
    parser.threads_pids[parser.last_data_newthread.tid] = parser.last_data_newthread.pid
    return parser.last_data_newthread


def handle_trace_data_exec(parser, events):
    result = events[0].values
    parser.last_data_exec = TraceDataExec(events, result[0], result[1], result[2])
    return parser.last_data_exec


def handle_trace_string_global(parser, events):
    debugid = 0
    str_id = 0
    vstr = b''
    lookup_events = []
    for event in events:
        lookup_events.append(event)
        if event.func_qualifier & DgbFuncQual.DBG_FUNC_START.value:
            debugid = event.values[0]
            str_id = event.values[1]
            vstr += event.data[16:]
        else:
            vstr += event.data

        if event.func_qualifier & DgbFuncQual.DBG_FUNC_END.value:
            break
    event = TraceStringGlobal(lookup_events, debugid, str_id, vstr.replace(b'\x00', b'').decode())
    if event.vstr:
        parser.global_strings[event.str_id] = event.vstr
    return event


def handle_trace_string_newthread(parser, events):
    event = TraceStringNewthread(events, events[0].data.replace(b'\x00', b'').decode())
    parser.pids_names[parser.last_data_newthread.pid] = event.name
    return event


def handle_trace_string_exec(parser, events):
    event = TraceStringExec(events, events[0].data.replace(b'\x00', b'').decode())
    parser.pids_names[parser.last_data_exec.pid] = event.name
    return event


handlers = {
    'TRACE_DATA_NEWTHREAD': handle_trace_data_newthread,
    'TRACE_DATA_EXEC': handle_trace_data_exec,
    'TRACE_STRING_GLOBAL': handle_trace_string_global,
    'TRACE_STRING_NEWTHREAD': handle_trace_string_newthread,
    'TRACE_STRING_EXEC': handle_trace_string_exec,
}

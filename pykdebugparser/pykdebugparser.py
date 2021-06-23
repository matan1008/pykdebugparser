from datetime import datetime
import io

from pygments import highlight, lexers, formatters

from pykdebugparser.kd_buf_parser import KdBufParser, ProcessData
from pykdebugparser.kevent import DgbFuncQual
from pykdebugparser.trace_codes import default_trace_codes
from pykdebugparser.traces_parser import TracesParser

c_lexer = lexers.CLexer()
color_formatter = formatters.TerminalTrueColorFormatter(style='stata-dark')


class PyKdebugParser:
    def __init__(self):
        self.filter_tid = None
        self.show_timestamp = True
        self.show_name = True
        self.show_func_qual = True
        self.show_tid = False
        self.show_process = True
        self.show_args = True
        self.color = True
        self.numer = None
        self.denom = None
        self.mach_absolute_time = None
        self.usecs_since_epoch = None
        self.timezone = None
        self.thread_map = {}

    def kevents(self, kdebug: io.IOBase):
        events_generator = KdBufParser(thread_map=self.thread_map).parse(kdebug)
        if self.filter_tid is not None:
            events_generator = filter(lambda e: e.tid != self.filter_tid, events_generator)
        return events_generator

    def formatted_kevents(self, kdebug: io.IOBase, trace_codes=None):
        trace_codes_map = default_trace_codes() if trace_codes is None else trace_codes
        return map(lambda e: self._format_kevent(e, trace_codes_map, self.thread_map), self.kevents(kdebug))

    def traces(self, kdebug: io.IOBase, trace_codes=None):
        trace_codes_map = default_trace_codes() if trace_codes is None else trace_codes
        traces_parser = TracesParser(trace_codes_map, self.thread_map)
        return traces_parser.feed_generator(self.kevents(kdebug))

    def formatted_traces(self, kdebug: io.IOBase, trace_codes=None):
        return map(lambda t: self._format_trace(t, self.thread_map), self.traces(kdebug, trace_codes))

    def _format_timestamp(self, timestamp):
        if None in (self.mach_absolute_time, self.numer, self.denom, self.usecs_since_epoch, self.timezone):
            return str(timestamp) + ' '
        offset_usec = (
                ((timestamp - self.mach_absolute_time) * self.numer) / (self.denom * 1000)
        )
        ts = datetime.fromtimestamp((self.usecs_since_epoch + offset_usec) / 1000000, tz=self.timezone)
        time_string = ts.strftime('%Y-%m-%d %H:%M:%S.%f')
        return f'{time_string:<27}'

    def _format_kevent(self, event, trace_codes_map, thread_map):
        if event.eventid in trace_codes_map:
            name = trace_codes_map[event.eventid] + f' ({hex(event.eventid)})'
        else:
            # Some event IDs are not public.
            name = hex(event.eventid)
        try:
            process = thread_map[event.tid]
        except KeyError:
            process = ProcessData(pid=-1, name='')
        formatted_data = ''
        if self.show_timestamp:
            formatted_data += self._format_timestamp(event.timestamp)
        formatted_data += f'{name:<58}' if self.show_name else ''
        if self.show_func_qual:
            try:
                formatted_data += f'{DgbFuncQual(event.func_qualifier).name:<15}'
            except ValueError:
                formatted_data += f'''{'Error':<16}'''
        formatted_data += f'{hex(event.tid):<12}' if self.show_tid else ''
        if self.show_process:
            process_rep = (f'{process.name}({process.pid})'
                           if process.pid != -1
                           else f'Error: tid {event.tid}')
            formatted_data += f'{process_rep:<27}'
        formatted_data += f'{str(event.data):<34}' if self.show_args else ''
        return formatted_data

    def _format_trace(self, trace, thread_map):
        tid = trace.ktraces[0].tid
        try:
            process = thread_map[tid]
        except KeyError:
            process = ProcessData(pid=-1, name='')

        formatted_data = ''
        if self.show_timestamp:
            formatted_data += self._format_timestamp(trace.ktraces[0].timestamp)
        formatted_data += f'{tid:>11} ' if self.show_tid else ''
        process_rep = (f'{process.name}({process.pid})'
                       if process.pid != -1
                       else f'Error: tid {tid}')
        formatted_data += f'{process_rep:<34}'
        event_rep = str(trace)
        if self.color:
            event_rep = highlight(event_rep, c_lexer, color_formatter).strip()

        return formatted_data + event_rep

import errno
import io
import json
import re
import signal
import sys
from itertools import islice

import click

from pykdebugparser.host_trace import DEFAULT_BUFFER_EVENTS, HostTrace, TraceLagError
from pykdebugparser.kd_buf_parser import KdBufParser
from pykdebugparser.line_filter import MATCH_HELP, LineFilter, emphasize
from pykdebugparser.pykdebugparser import PyKdebugParser
from pykdebugparser.selection import BSC_SUBCLASS, GROUP_HELP, Selection, captured_events, parse_live_selection
from pykdebugparser.trace_codes import EVENT_GROUP_PREFIXES, SYSCALL_GROUPS, default_trace_codes, event_eventids, \
    syscall_eventids


@click.group()
def cli():
    pass


def print_with_count(generator, count: int):
    i = 0
    for obj in generator:
        if i == count:
            break
        print(obj)
        i += 1


class BasedIntParamType(click.ParamType):
    name = 'based int'

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f'{value!r} is not a valid int.', param, ctx)


BASED_INT = BasedIntParamType()

dump_input = click.argument('kdebug_dump', type=click.File('rb'))
count = click.option('-c', '--count', type=click.INT, default=-1,
                     help='Number of events to print. Omit to endless sniff.')
tid_filter = click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
show_tid = click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
process_filter = click.option('--process', default=None, help='Process ID / name to filter. Omit for all.')
class_filter = click.option('-cf', '--class-filters', multiple=True, type=BASED_INT,
                            help='Events class filter. Omit for all.')
subclass_filter = click.option('-sf', '--subclass-filters', multiple=True, type=BASED_INT,
                               help='Events subclass filter. Omit for all.')


@cli.command()
@dump_input
@count
@tid_filter
@show_tid
@class_filter
@subclass_filter
def kevents(kdebug_dump, count, tid, show_tid, class_filters, subclass_filters):
    """Print the raw kevents of a kdebug dump."""
    parser = PyKdebugParser()
    parser.filter_class = class_filters
    parser.filter_subclass = subclass_filters
    parser.filter_tid = tid
    parser.show_tid = show_tid
    print_with_count(parser.formatted_kevents(kdebug_dump), count)


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
@class_filter
@subclass_filter
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
def traces(kdebug_dump, count, tid, process, show_tid, class_filters, subclass_filters, color):
    """Print the traces (syscalls, thread events, etc.) of a kdebug dump."""
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.filter_class = list(class_filters)
    parser.filter_subclass = list(subclass_filters)
    parser.show_tid = show_tid
    parser.color = color
    print_with_count(parser.formatted_traces(kdebug_dump), count)


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
def callstacks(kdebug_dump, count, tid, process, show_tid):
    """Print the callstacks (PERF events) of a kdebug dump."""
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_callstacks(kdebug_dump), count)


@cli.command()
@dump_input
def processes(kdebug_dump):
    """Print the processes listed in a kdebug dump (version 3, such as ktrace's), as JSON."""
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.processes, indent=4))


@cli.command()
@dump_input
def kexts(kdebug_dump):
    """Print the kernel extensions listed in a kdebug dump (version 3, such as ktrace's), as JSON."""
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.kernel_extensions, indent=4))


@cli.command()
@dump_input
def images(kdebug_dump):
    """Print the images listed in a kdebug dump (version 3, such as ktrace's), as JSON."""
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.images, indent=4))


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
def logs(kdebug_dump, count, tid, process, show_tid):
    """Print the os_log messages of a kdebug dump."""
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_logs(kdebug_dump), count)


DBG_BSD = 4
# Subclass of VFS_LOOKUP, which names the paths of BSD syscalls.
DBG_FSRW = 0x0301
# How far (in seconds) parse-live may fall behind the system before it skips ahead to recent events.
PARSE_LIVE_MAX_LAG = 2.0

_ANSI_RESET = '\033[0m'
_ANSI_TS = '\033[2;36m'
_ANSI_TID = '\033[35m'
_ANSI_PROCESS = '\033[33m'
_ANSI_EVENT = '\033[32m'


def _colorize_columns(trace: str, show_tid: bool) -> str:
    """Color the columns of a formatted trace, by their fixed widths."""
    ts_end = 27
    tid_end = ts_end + (12 if show_tid else 0)
    process_end = tid_end + 34
    if len(trace) < process_end:
        return trace
    colored_trace = f'{_ANSI_TS}{trace[:ts_end]}{_ANSI_RESET}'
    if show_tid:
        colored_trace += f'{_ANSI_TID}{trace[ts_end:tid_end]}{_ANSI_RESET}'
    colored_trace += f'{_ANSI_PROCESS}{trace[tid_end:process_end]}{_ANSI_RESET}'
    return colored_trace + f'{_ANSI_EVENT}{trace[process_end:]}{_ANSI_RESET}'


def _validate_syscalls(ctx, param, names):
    try:
        syscall_eventids(names)
    except ValueError as e:
        raise click.BadParameter(f'{e} (`pykdebugparser events` lists them as BSC_<name>)')
    return names


def _validate_events(ctx, param, names):
    try:
        event_eventids(names)
    except ValueError as e:
        raise click.BadParameter(f'{e} (`pykdebugparser events` lists them)')
    return names


def _validate_regexes(ctx, param, regexes):
    for regex in regexes:
        try:
            re.compile(regex)
        except re.error as e:
            raise click.BadParameter(f'{regex!r}: {e}')
    return regexes


def _raise_system_exit(signum, frame):
    raise SystemExit(128 + signum)


@cli.command()
@count
@tid_filter
@process_filter
@show_tid
@class_filter
@subclass_filter
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
@click.option('-b', '--buffer-events', type=click.INT, default=DEFAULT_BUFFER_EVENTS, show_default=True,
              help='Kernel trace buffer size, in events.')
def live(count, tid, process, show_tid, class_filters, subclass_filters, color, buffer_events):
    """
    Print traces of this Mac in real time (requires root).

    Class and subclass filters are applied by the kernel, narrowing them lets the trace keep up with a busy system.
    """
    kernel_subclasses = list(subclass_filters)
    if DBG_BSD in class_filters or any(sc >> 8 == DBG_BSD for sc in subclass_filters):
        kernel_subclasses.append(DBG_FSRW)
    # Stop tracing on SIGTERM and SIGHUP too, the kernel trace facility is global.
    handlers = {signum: signal.signal(signum, _raise_system_exit) for signum in (signal.SIGTERM, signal.SIGHUP)}
    try:
        with HostTrace(class_filters, kernel_subclasses, buffer_events=buffer_events) as trace:
            parser = PyKdebugParser()
            trace.configure_parser(parser)
            parser.filter_tid = tid
            parser.filter_process = process
            parser.filter_class = list(class_filters)
            parser.filter_subclass = list(subclass_filters)
            parser.show_tid = show_tid
            parser.color = color
            try:
                print_with_count(parser.formatted_traces(trace), count)
            except KeyboardInterrupt:
                pass
        click.echo(f'Read {trace.events} events, the kernel dropped events {trace.lost_events} times', err=True)
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            raise click.ClickException('Tracing requires root, run with sudo')
        if e.errno == errno.EBUSY:
            raise click.ClickException('Tracing is in use by another process (such as ktrace, fs_usage or '
                                       'Instruments)')
        raise
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


def _selection_options(func):
    """The options that select what parse-live prints, shared by `parse-live` and `events` (and pymobiledevice3's)."""
    options = [
        click.option('--bsc', is_flag=True, help='The BSD syscalls.'),
        class_filter,
        subclass_filter,
        click.option('-s', '--syscall', 'syscalls', multiple=True, callback=_validate_syscalls,
                     help='This syscall (e.g. open, openat; with its _nocancel and _dprotected_np variants), with its '
                          'paths. Can be specified multiple times.'),
        click.option('-e', '--event', 'events', multiple=True, callback=_validate_events,
                     help='This event, by its trace code name (e.g. DBG_DYLD_TIMING_DLSYM; `events TEXT` finds the '
                          'name). Can be specified multiple times.'),
        *(click.option(f'--{group}', f'group_{group}', is_flag=True, help=GROUP_HELP[group])
          for group in SYSCALL_GROUPS),
        click.option('--dyld', is_flag=True, help='dyld events (image loads, dlopen, dlsym, ...), filtered by the kernel.'),
        *(click.option(f'--{group}', f'group_{group}', is_flag=True, help=GROUP_HELP[group])
          for group in EVENT_GROUP_PREFIXES),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _selection(bsc, class_filters, subclass_filters, syscalls, events, dyld, groups) -> Selection:
    return parse_live_selection(bsc=bsc, class_filters=class_filters, subclass_filters=subclass_filters,
                                syscalls=syscalls, events=events, dyld=dyld,
                                groups=[group[len('group_'):] for group, on in groups.items() if on])


@cli.command('parse-live')
@count
@tid_filter
@process_filter
@show_tid
@_selection_options
@click.option('-m', '--match', multiple=True, help=MATCH_HELP['match'])
@click.option('-v', '--invert-match', multiple=True, help=MATCH_HELP['invert_match'])
@click.option('-mi', '--match-insensitive', multiple=True, help=MATCH_HELP['match_insensitive'])
@click.option('-vi', '--invert-match-insensitive', multiple=True, help=MATCH_HELP['invert_match_insensitive'])
@click.option('-r', '--regex', multiple=True, callback=_validate_regexes, help=MATCH_HELP['regex'])
@click.option('-ri', '--insensitive-regex', multiple=True, callback=_validate_regexes,
              help=MATCH_HELP['insensitive_regex'])
@click.option('--json', 'json_output', is_flag=True,
              help='Print each trace as a JSON object, one per line: its time, thread, process, event name, parsed '
                   'fields and text. The filters match the line it would print.')
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
@click.option('--color-mode', type=click.Choice(['rich', 'fast'], case_sensitive=False), default='rich',
              show_default=True,
              help="Trace color style: 'rich' also colors the event by what it shows (call, strings, numbers, errors, "
                   "...), 'fast' colors only the columns.")
@click.option('--skip-behind/--no-skip-behind', default=False, show_default=True,
              help='Skip ahead to recent events whenever output falls more than --max-lag behind the system, instead of '
                   'failing. Without class/subclass filters the system can trace events faster than they can be parsed.')
@click.option('--max-lag', type=click.FloatRange(min=0, min_open=True), default=PARSE_LIVE_MAX_LAG, show_default=True,
              help='How far (in seconds) output may fall behind the system before it skips ahead (--skip-behind) or '
                   'fails (--no-skip-behind).')
@click.option('-b', '--buffer-events', type=click.INT, default=DEFAULT_BUFFER_EVENTS, show_default=True,
              help='Kernel trace buffer size, in events.')
def parse_live(count, tid, process, show_tid, bsc, class_filters, subclass_filters, syscalls, events, dyld, match,
               invert_match, match_insensitive, invert_match_insensitive, regex, insensitive_regex, json_output, color,
               color_mode, skip_behind, max_lag, buffer_events, **groups):
    """
    Print traces (syscalls, thread events, etc.) of this Mac in real time (requires root).

    The selections add up. The kernel filters by subclass at best, so the events not selected are dropped right after
    decoding. `events` with the same options lists the events that are printed.
    """
    selection = _selection(bsc, class_filters, subclass_filters, syscalls, events, dyld, groups)
    class_filters = selection.classes
    subclass_filters = selection.subclasses
    # The kernel filters by subclass at best: trace every syscall (and the subclass of each event), and filter the
    # chosen ones while parsing.
    kernel_subclasses = subclass_filters + ([BSC_SUBCLASS] if selection.syscall_ids else [])
    kernel_subclasses += sorted({eventid >> 16 for eventid in selection.event_ids})
    if DBG_BSD in class_filters or any(sc >> 8 == DBG_BSD for sc in kernel_subclasses):
        kernel_subclasses.append(DBG_FSRW)
    line_filter = LineFilter(match, invert_match, match_insensitive, invert_match_insensitive, regex, insensitive_regex)
    colored_columns = color and color_mode.lower() == 'fast'
    # Lines are written in batches, and flushed whenever the trace waits for events: a write per line (what a
    # line-buffered terminal does) costs a busy trace up to half its speed.
    out = sys.stdout

    def warn_skipped(skipped, lag):
        out.flush()
        click.echo(f'Skipped {skipped} events to catch up ({lag:.1f}s behind); narrow the trace with '
                   f'--class-filters/--subclass-filters/--bsc to see every event', err=True)

    # Stop tracing on SIGTERM and SIGHUP too, the kernel trace facility is global.
    handlers = {signum: signal.signal(signum, _raise_system_exit) for signum in (signal.SIGTERM, signal.SIGHUP)}
    line_buffering = isinstance(out, io.TextIOWrapper) and out.line_buffering
    if line_buffering:
        out.reconfigure(line_buffering=False)
    try:
        with HostTrace(class_filters, kernel_subclasses, buffer_events=buffer_events,
                       max_lag=max_lag, skip_behind=skip_behind, on_skip=warn_skipped, on_wait=out.flush) as trace:
            parser = PyKdebugParser()
            trace.configure_parser(parser)
            parser.filter_tid = tid
            parser.filter_process = process
            parser.filter_class = class_filters
            parser.filter_subclass = subclass_filters
            parser.filter_eventid = selection.eventids
            parser.line_filter = line_filter
            parser.show_tid = show_tid
            parser.color = color and not colored_columns
            write = out.write
            try:
                if json_output:
                    for trace_dict in islice(parser.dict_traces(trace), None if count < 0 else count):
                        write(json.dumps(trace_dict) + '\n')
                else:
                    if show_tid:
                        write('{:^27}|{:^11}|{:^33}|   Event\n'.format('Time', 'Thread', 'Process'))
                    else:
                        write('{:^27}|{:^33}|   Event\n'.format('Time', 'Process'))
                    for line in islice(parser.formatted_traces(trace), None if count < 0 else count):
                        if colored_columns:
                            plain = line
                            line = _colorize_columns(line, show_tid)
                            if line_filter:
                                line = emphasize(line, line_filter.spans(plain))
                        write(line + '\n')
            except KeyboardInterrupt:
                pass
            finally:
                out.flush()
                # Whether the trace kept up with the system: nothing dropped by the kernel, nothing skipped.
                click.echo(f'Read {trace.events} events, the kernel dropped events {trace.lost_events} times, '
                           f'{trace.skipped_events} events were skipped to catch up', err=True)
    except TraceLagError as e:
        raise click.ClickException(f'{e}. To skip ahead to recent events instead, pass --skip-behind (or allow more '
                                   f'lag with --max-lag, or narrow the trace)')
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            raise click.ClickException('Tracing requires root, run with sudo')
        if e.errno == errno.EBUSY:
            raise click.ClickException('Tracing is in use by another process (such as ktrace, fs_usage or '
                                       'Instruments)')
        raise
    finally:
        if line_buffering:
            out.reconfigure(line_buffering=True)
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


@cli.command()
@click.argument('pattern', required=False)
@_selection_options
def events(pattern, bsc, class_filters, subclass_filters, syscalls, events, dyld, **groups):
    """
    List the events `parse-live` prints with the same options (e.g. `events --fs`, `events -s open`), or every event
    name `parse-live --event` accepts.

    PATTERN only lists the names containing it, ignoring case (e.g. dlsym).
    """
    if bsc or class_filters or subclass_filters or syscalls or events or dyld or any(groups.values()):
        names = captured_events(_selection(bsc, class_filters, subclass_filters, syscalls, events, dyld, groups))
    else:
        names = sorted(set(default_trace_codes().values()))
    if pattern is not None:
        names = [name for name in names if pattern.lower() in name.lower()]
    for name in names:
        print(name)


if __name__ == '__main__':
    cli()

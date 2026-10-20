import errno
import io
import json
import signal
import sys
from itertools import islice

import click

from pykdebugparser.host_trace import DEFAULT_BUFFER_EVENTS, HostTrace, TraceLagError
from pykdebugparser.kd_buf_parser import KdBufParser
from pykdebugparser.pykdebugparser import PyKdebugParser
from pykdebugparser.trace_codes import SYSCALL_GROUPS, default_trace_codes, event_eventids, group_mach_traps, \
    syscall_eventids, syscall_names


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
# Subclass of the BSD syscalls.
BSC_SUBCLASS = 0x040c
DBG_DYLD = 0x1f
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
        raise click.BadParameter(f'{e} (the `syscalls` command lists them)')
    return names


def _validate_events(ctx, param, names):
    try:
        event_eventids(names)
    except ValueError as e:
        raise click.BadParameter(f'{e} (the `events` command lists them)')
    return names


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


def _group_option(group, help_):
    return click.option(f'--{group}', f'group_{group}', is_flag=True, help=f'{help_} (`syscalls --group {group}`).')


@cli.command('parse-live')
@count
@tid_filter
@process_filter
@show_tid
@class_filter
@subclass_filter
@click.option('--bsc', is_flag=True, help='Print the BSD syscalls.')
@click.option('-s', '--syscall', 'syscalls', multiple=True, callback=_validate_syscalls,
              help='Only print this syscall (e.g. open, openat; with its _nocancel variant), with its paths. Can be '
                   'specified multiple times; the `syscalls` command lists the names. The kernel can only filter whole '
                   'subclasses, so it traces every syscall and the others are dropped right after decoding.')
@click.option('-e', '--event', 'events', multiple=True, callback=_validate_events,
              help='Only print this event (a trace code name, e.g. DBG_DYLD_TIMING_DLOPEN). Can be specified multiple '
                   'times; the `events` command lists the names. The kernel traces the event\'s whole subclass, and '
                   'the other events in it are dropped right after decoding.')
@_group_option('fs', 'Print the syscalls that take a path')
@_group_option('net', 'Print the socket syscalls')
@_group_option('proc', 'Print the process lifecycle syscalls')
@_group_option('io', 'Print the syscalls on file descriptors: read, write, ...')
@_group_option('mem', 'Print memory mapping syscalls and Mach traps')
@_group_option('signal', 'Print the signal syscalls')
@_group_option('cred', 'Print credential, code signing and policy checks, and access to other tasks')
@_group_option('sync', 'Print locks, condition variables, kqueues and workqueues')
@_group_option('mach', 'Print the Mach traps')
@click.option('--dyld', is_flag=True, help='Print dyld events (image loads, dlopen, dlsym, ...).')
@click.option('--json', 'json_output', is_flag=True,
              help='Print each trace as a JSON object, one per line: its time, thread, process, event name, parsed '
                   'fields and text.')
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
@click.option('--color-mode', type=click.Choice(['rich', 'fast'], case_sensitive=False), default='rich',
              show_default=True,
              help="Trace color style: 'rich' also colors the event by what it shows (call, strings, numbers, errors, "
                   "...), 'fast' colors only the columns.")
@click.option('--skip-behind/--no-skip-behind', default=True, show_default=True,
              help='Skip ahead to recent events whenever output falls more than --max-lag behind the system, instead of '
                   'failing. Without class/subclass filters the system can trace events faster than they can be parsed.')
@click.option('--max-lag', type=click.FloatRange(min=0, min_open=True), default=PARSE_LIVE_MAX_LAG, show_default=True,
              help='How far (in seconds) output may fall behind the system before it skips ahead (--skip-behind) or '
                   'fails (--no-skip-behind).')
@click.option('-b', '--buffer-events', type=click.INT, default=DEFAULT_BUFFER_EVENTS, show_default=True,
              help='Kernel trace buffer size, in events.')
def parse_live(count, tid, process, show_tid, class_filters, subclass_filters, bsc, syscalls, events, dyld,
               json_output, color, color_mode, skip_behind, max_lag, buffer_events, **groups):
    """
    Print traces (syscalls, thread events, etc.) of this Mac in real time (requires root).

    Class and subclass filters are applied by the kernel, narrowing them lets the trace keep up with a busy system.
    """
    # Groups add up: each one adds its syscalls and Mach traps to what is printed.
    groups = [group[len('group_'):] for group, on in groups.items() if on]
    syscall_ids = syscall_eventids([*syscalls, *(name for group in groups for name in SYSCALL_GROUPS[group])])
    event_ids = event_eventids([*events, *(name for group in groups for name in group_mach_traps(group))])
    class_filters = list(class_filters) + ([DBG_DYLD] if dyld else [])
    subclass_filters = list(subclass_filters) + ([BSC_SUBCLASS] if bsc else [])
    # The kernel filters by subclass at best: trace every syscall (and the subclass of each event), and filter the
    # chosen ones while parsing.
    kernel_subclasses = subclass_filters + ([BSC_SUBCLASS] if syscall_ids else [])
    kernel_subclasses += sorted({eventid >> 16 for eventid in event_ids})
    if DBG_BSD in class_filters or any(sc >> 8 == DBG_BSD for sc in kernel_subclasses):
        kernel_subclasses.append(DBG_FSRW)
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
            parser.filter_eventid = syscall_ids | event_ids
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
                            line = _colorize_columns(line, show_tid)
                        write(line + '\n')
            except KeyboardInterrupt:
                pass
            finally:
                out.flush()
                # Whether the trace kept up with the system: nothing dropped by the kernel, nothing skipped.
                click.echo(f'Read {trace.events} events, the kernel dropped events {trace.lost_events} times, '
                           f'{trace.skipped_events} events were skipped to catch up', err=True)
    except TraceLagError as e:
        raise click.ClickException(f'{e}: narrow the trace, raise --max-lag, or use --skip-behind')
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
def events():
    """List the event names that `parse-live --event` accepts."""
    for name in sorted(set(default_trace_codes().values())):
        print(name)


@cli.command()
@click.option('--group', type=click.Choice(list(SYSCALL_GROUPS)),
              help='Only list the syscalls and Mach traps of this parse-live group (--fs, ...).')
def syscalls(group):
    """List the syscall names that `parse-live --syscall` accepts, or the syscalls and Mach traps of a group."""
    names = syscall_names() if group is None else [*SYSCALL_GROUPS[group], *group_mach_traps(group)]
    for name in names:
        print(name)


if __name__ == '__main__':
    cli()

import errno
import json
import signal

import click

from pykdebugparser.host_trace import DEFAULT_BUFFER_EVENTS, HostTrace
from pykdebugparser.kd_buf_parser import KdBufParser
from pykdebugparser.pykdebugparser import PyKdebugParser


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
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_callstacks(kdebug_dump), count)


@cli.command()
@dump_input
def processes(kdebug_dump):
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.processes, indent=4))


@cli.command()
@dump_input
def kexts(kdebug_dump):
    parser = KdBufParser({}, {})
    list(parser.parse(kdebug_dump))
    print(json.dumps(parser.kernel_extensions, indent=4))


@cli.command()
@dump_input
def images(kdebug_dump):
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
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
    parser.show_tid = show_tid
    print_with_count(parser.formatted_logs(kdebug_dump), count)


DBG_BSD = 4
# Subclass of VFS_LOOKUP, which names the paths of BSD syscalls.
DBG_FSRW = 0x0301


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


if __name__ == '__main__':
    cli()

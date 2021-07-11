import click

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


dump_input = click.argument('kdebug_dump', type=click.File('rb'))
count = click.option('-c', '--count', type=click.INT, default=-1,
                     help='Number of events to print. Omit to endless sniff.')
tid_filter = click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
show_tid = click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
process_filter = click.option('--process', default=None, help='Process ID / name to filter. Omit for all.')


@cli.command()
@dump_input
@count
@tid_filter
@show_tid
def kevents(kdebug_dump, count, tid, show_tid):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.show_tid = show_tid
    print_with_count(parser.formatted_kevents(kdebug_dump), count)


@cli.command()
@dump_input
@count
@tid_filter
@process_filter
@show_tid
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
def traces(kdebug_dump, count, tid, process, show_tid, color):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.filter_process = process
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


if __name__ == '__main__':
    cli()

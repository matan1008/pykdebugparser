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


@cli.command()
@click.argument('kdebug_dump', type=click.File('rb'))
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
def kevents(kdebug_dump, count, tid, show_tid):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.show_tid = show_tid
    print_with_count(parser.formatted_kevents(kdebug_dump), count)


@cli.command()
@click.argument('kdebug_dump', type=click.File('rb'))
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
def traces(kdebug_dump, count, tid, show_tid, color):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.show_tid = show_tid
    parser.color = color
    print_with_count(parser.formatted_traces(kdebug_dump), count)


@cli.command()
@click.argument('kdebug_dump', type=click.File('rb'))
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
def callstacks(kdebug_dump, count, tid):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    print_with_count(parser.formatted_callstacks(kdebug_dump), count)


if __name__ == '__main__':
    cli()

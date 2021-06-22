import click

from pykdebugparser.pykdebugparser import PyKdebugParser


@click.command()
@click.argument('kdebug_dump', type=click.File('rb'))
@click.option('-c', '--count', type=click.INT, default=-1, help='Number of events to print. Omit to endless sniff.')
@click.option('--tid', type=click.INT, default=None, help='Thread ID to filter. Omit for all.')
@click.option('--show-tid/--no-show-tid', default=False, help='Whether to print thread id or not.')
@click.option('--color/--no-color', default=True, help='Whether to print with color or not.')
def traces_from_file(kdebug_dump, count, tid, show_tid, color):
    parser = PyKdebugParser()
    parser.filter_tid = tid
    parser.show_tid = show_tid
    parser.color = color

    if show_tid:
        print('{:^26}|{:^11}|{:^33}|   Event'.format('Time', 'Thread', 'Process'))
    else:
        print('{:^26}|{:^33}|   Event'.format('Time', 'Process'))

    i = 0
    for trace in parser.formatted_traces(kdebug_dump):
        if i == count:
            break
        print(trace)
        i += 1


def cli():
    traces_from_file()


if __name__ == '__main__':
    cli()

[![Python application](https://github.com/matan1008/pykdebugparser/workflows/Python%20application/badge.svg)](https://github.com/matan1008/pykdebugparser/actions/workflows/python-app.yml "Python application action")
[![Pypi version](https://img.shields.io/pypi/v/pykdebugparser.svg)](https://pypi.org/project/pykdebugparser/ "PyPi package")
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/matan1008/pykdebugparser.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/matan1008/pykdebugparser/context:python)


- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
  * [Example](#example)


# Description

`pykdebugparser` is a utility created in order to parse Darwin's (iOS and OSX) kdebug events.

The main difference between `pykdebugparser` and other utilities like fs_usage and ktrace is the traces parsing and
formatting.

# Installation

Install the last released version using `pip`:

```shell
python3 -m pip install --user -U pykdebugparser
```

Or install the latest version from sources:

```shell
git clone git@github.com:matan1008/pykdebugparser.git
cd pykdebugparser
python3 -m pip install --user -U -e .
```

# Usage

You can either use the CLI:

```
Usage: pykdebugparser [OPTIONS] KDEBUG_DUMP

Options:
  -c, --count INTEGER         Number of events to print. Omit to endless
                              sniff.
  --tid INTEGER               Thread ID to filter. Omit for all.
  --show-tid / --no-show-tid  Whether to print thread id or not.
  --color / --no-color        Whether to print with color or not.
  --help                      Show this message and exit.
```

Or import and use the API yourself:

```python
from pykdebugparser.pykdebugparser import PyKdebugParser

parser = PyKdebugParser()
parser.color = True
with open('kdebug.bin', 'rb') as fd:
    for trace in parser.formatted_traces(fd):
        print(trace)
```

## Example

In order to produce an input file, you can use `ktrace dump`, you can see an example [here](https://terminalizer.com/view/8514aef95032)


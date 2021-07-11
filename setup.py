import os

from setuptools import setup, find_packages

BASE_DIR = os.path.realpath(os.path.dirname(__file__))
VERSION = '1.1.1'


def parse_requirements():
    reqs = []
    if os.path.isfile(os.path.join(BASE_DIR, 'requirements.txt')):
        with open(os.path.join(BASE_DIR, 'requirements.txt'), 'r') as fd:
            for line in fd.readlines():
                line = line.strip()
                if line:
                    reqs.append(line)
    return reqs


def get_description():
    with open(os.path.join(BASE_DIR, 'README.md'), 'r') as fh:
        return fh.read()


if __name__ == '__main__':
    setup(
        version=VERSION,
        name='pykdebugparser',
        description='Python parser for kdebug events',
        long_description=get_description(),
        long_description_content_type='text/markdown',
        cmdclass={},
        packages=find_packages(),
        package_data={'': ['*.txt', '*.TXT', '*.codes']},
        data_files=[('.', ['requirements.txt'])],
        author='Matan Perelman',
        install_requires=parse_requirements(),
        entry_points={
            'console_scripts': ['pykdebugparser=pykdebugparser.__main__:cli'],
        },
        classifiers=[
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
        ],
        url='https://github.com/matan1008/pykdebugparser',
        project_urls={
            'pykdebugparser': 'https://github.com/matan1008/pykdebugparser'
        },
        tests_require=['pytest'],
    )

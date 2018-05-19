#!/usr/bin/env python3

from distutils.core import setup

package_name = 'csv2cmi'
filename = package_name + '.py'


def get_version():
    import ast
    with open(filename) as input_file:
        for line in input_file:
            if line.startswith('__version__'):
                return ast.parse(line).body[0].value.s


def get_long_description():
    try:
        with open('README.md', 'r') as f:
            return f.read()
    except IOError:
        return ''


setup(
    name=package_name,
    version=get_version(),
    description='converts a table of letters into CMI format',
    long_description=get_long_description(),
    author='Klaus Rettinghaus',
    author_email='rettinghaus@bach-leipzig.de',
    url='https://github.com/saw-leipzig/csv2cmi',
    py_modules=[package_name],
    license='License :: OSI Approved :: MIT License',
)

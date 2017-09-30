#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys

if sys.version_info >= (3, 0):
    raise SystemExit('py2-ipaddress: For Python 3.x, please use the official ipaddress module.')

from setuptools import setup

setup(
    name='py2-ipaddress',
    version='3.4.1',
    description="Python 2.6 backport of 3.4's ipaddress module",
    maintainer='Søren Løvborg',
    maintainer_email='kwi@kwi.dk',
    url='https://bitbucket.org/kwi/py2-ipaddress/',
    license='Python Software Foundation License version 2',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Python Software Foundation License',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: System :: Networking',
    ],

    long_description=open('README.rst', 'r').read(),
    py_modules=[ 'ipaddress' ],
    zip_safe=True,
)

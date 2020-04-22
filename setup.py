# -*- coding:utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open("VERSION") as f1, open("README.md") as f2:
    VERSION = f1.read().strip()
    LONG_DESCRIPTION = f2.read()

kw = {
    "version": VERSION,
    "name": "uio",
    "keywords": ["json", "micro", "HTTP"],
    "author": "THOORENS Bruno",
    "author_email": "moustikitos@gmail.com",
    "maintainer": "THOORENS Bruno",
    "maintainer_email": "moustikitos@gmail.com",
    "url": "https://github.com/Moustikitos/micro-io",
    "download_url":
        "https://github.com/Moustikitos/micro-io/archive/master.zip",
    "include_package_data": True,
    "description": "Low footprint HTTP stuff with JSON",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["uio"],
    "install_requires": [],
    "license": "Cpyright 2020 - THOORENS Bruno",
    "classifiers": [
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
}

setup(**kw)

# -*- coding:utf-8 -*-

from setuptools import setup


with open("VERSION") as f1, open("README.md") as f2:
    VERSION = f1.read().strip()
    LONG_DESCRIPTION = f2.read()

kw = {
    "version": VERSION,
    "name": "usrv",
    "keywords": ["micro", "framework", "HTTP"],
    "author": "THOORENS Bruno",
    "author_email": "moustikitos@gmail.com",
    "maintainer": "THOORENS Bruno",
    "maintainer_email": "moustikitos@gmail.com",
    "url": "https://moustikitos.github.io/micro-server",
    "project_urls": {  # Optional
        "Bug Reports": "https://github.com/Moustikitos/micro-server/issues",
        "Funding": "https://github.com/Moustikitos/micro-server/?tab=readme-ov-file#support-this-project",
        "Source": "https://github.com/Moustikitos/micro-server",
    },
    "download_url":
        "https://github.com/Moustikitos/micro-server/archive/master.zip",
    "include_package_data": True,
    "description": "Pure python micro web framework",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["usrv"],
    "install_requires": ["waitress"],
    "license": "Cpyright 2020 - 2021 THOORENS Bruno",
    "classifiers": [
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    "entry_points": {
        "console_scripts": [
            "usrv_serve = wsgi_srv"
        ]
    }
}

setup(**kw)

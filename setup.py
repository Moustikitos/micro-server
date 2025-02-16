# -*- coding:utf-8 -*-
import os
import sys
from subprocess import call, PIPE
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from setuptools.command.build_clib import build_clib

try:
    from importlib import machinery
    lib_suffix = machinery.all_suffixes()[-1]
    install_requires = []
except ImportError:
    import imp
    lib_suffix = imp.get_suffixes()[0][0]
    install_requires = ['future']

class build_ctypes(build_ext):

    EXT = ".dll" if sys.platform.startswith("win") else lib_suffix

    def __init__(self, *args, **kw):
        build_clib_options = []
        for long_, short, comment in build_clib.user_options:
            build_clib_options.extend([long_, short])
        call(
            [sys.executable, 'setup.py', 'build_clib'] +
            [arg for arg in sys.argv if arg.lstrip("-") in build_clib_options],
            stdout=PIPE
        )
        build_ext.__init__(self, *args, **kw)

    def build_extension(self, ext):
        return super().build_extension(ext)

    def get_export_symbols(self, ext):
        return ext.export_symbols

    def get_ext_filename(self, ext_name):
        return ext_name + build_ctypes.EXT

if "static" in sys.argv:
    sys.argv.pop(sys.argv.index("static"))
    # configure compilation
    extra_compile_args = ["-Ofast"]
    include_dirs = [os.path.abspath('./src')]
    libraries = []
    if sys.platform.startswith("win"):
        # configuration using mingw compiler from Msys 2.x installed in C:/
        extra_link_args = [
            "-l:libpython%s.%s.a" % sys.version_info[:2],
            "-l:libgmp.a",
            "-l:libcrypto.a",
            "-static"
        ]
        library_dirs = [r'C:\Msys\usr\lib']
    else:
        extra_link_args = ["-l:libgmp.so", "-l:libcrypto.so"]
        library_dirs = []
else:
    # configure compilation
    extra_compile_args = ['-Ofast']
    include_dirs = [os.path.abspath('./src')]
    libraries = ['gmp', 'crypto']
    extra_link_args = []
    library_dirs = []

# configure libraries
libraries = [
    (
        "schnorr", {
            "sources": ["src/schnorr.c"],
            "extra_compile_args": extra_compile_args,
            "extra_link_args": extra_link_args,
            "include_dirs": include_dirs,
            "library_dirs": library_dirs,
            "libraries": libraries,
        }
    )
]

lib_schnorr = libraries[0]

cmd_class = {
    "build_ctypes": build_ctypes,
    "build_ext": build_ctypes
}

ext_modules = [
    Extension('usrv/_schnorr', **lib_schnorr[-1])
]

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
    "project_urls": {
        "Bug Reports": "https://github.com/Moustikitos/micro-server/issues",
        "Funding":
            "https://github.com/Moustikitos/micro-server/?tab=readme-ov-file#s"
            "upport-this-project",
        "Source": "https://github.com/Moustikitos/micro-server",
    },
    "download_url":
        "https://github.com/Moustikitos/micro-server/archive/master.zip",
    "include_package_data": True,
    "description": "Pure python micro web framework",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["usrv"],
    "install_requires": ["waitress", "pyaes"] + install_requires,
    "license": "Cpyright 2020 - 2021 THOORENS Bruno",
    "libraries": libraries,
    "ext_modules": ext_modules,
    "cmdclass": cmd_class,
    "classifiers": [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server"
    ],
    "entry_points": {
        "console_scripts": [
            "usrv_server = wsgi_srv",
            "usrv_client = clt"
        ]
    }
}

setup(**kw)

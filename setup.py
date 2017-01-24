# -*- coding: utf-8 -*-


from setuptools import setup


setup(
    name="td6502",
    version="0.1.0",

    description="6502 disassembler",
    long_description=open("README.rst").read(),
    license="GPLv3",

    url="https://github.com/taotao54321/td6502",
    author="TaoTao",
    author_email="taotao54321@gmail.com",

    classifiers=(
        "Development Status :: 1 - Planning",
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Disassemblers",
    ),

    keywords="6502 disassembler",

    packages=("td6502",),

    entry_points={
        "console_scripts" : (
            "td6502=td6502.__main__:dis_main",
            "td6502-analyze=td6502.__main__:ana_main",
        ),
    },
)

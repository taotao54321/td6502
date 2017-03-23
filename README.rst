======
td6502
======

6502 disassembler which has some code analysis feature. It can take
advantage of FCEUX CDL file.

This program is at very alpha stage.


Requirements
------------

* Python 3


Install
-------

.. code-block:: shell

  $ pip install [--user] [-e] .


Usage
-----

First, generate a program database with td6502-analyze:

.. code-block:: shell

  $ td6502-analyze --org=0x8000 --nmi=auto --reset=auto --irq=auto --plugin=nes --plugin=cdl_fceux:foo-PRG.cdl,0,1 foo-PRG.bin > program_db.py

And, generate a disassembly with td6502:

.. code-block:: shell

  $ td6502 --db=program_db.py foo-PRG.bin > foo.asm

If you use FCEUX CDL file, you have to extract the corresponding
region of the CDL file in advance. For example:

.. code-block:: shell

  $ dd if=foo.cdl of=foo-PRG.cdl bs=32768 count=1

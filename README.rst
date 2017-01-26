======
td6502
======

6502 disassembler.


Install
-------

.. code-block:: shell

  $ pip install [--user] [-e] .


Usage
-----

.. code-block:: shell

  $ td6502-analyze --org=0x8000 foo.bin > program_db.py
  $ td6502 --db=program_db.py foo.bin

or

.. code-block:: shell

  $ td6502-analyze --org=0x8000 foo.bin | td6502 --db=- foo.bin



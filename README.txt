findexecutables.py: Extracts executables from fat executables.

findexecutables.py is a command-line tool written in Python which can find
and extract executables from fat (and normal) executables.

A fat executable, fat binary or multi-architecture binary
(https://en.wikipedia.org/wiki/Mach-O#Multi-architecture_binaries) is an
executable binary program file which contains code for multiple
architectures. It's typical on macOS.

findexecutables.py supports the ELF (used on Linux, FreeBSD etc.; FatELF is
not supported) and Mach-O (used on macOS, iOS) formats as input.

findexecutables.py needs Python 2.4, 2.5, 2.6 or 2.7. Python 3.x won't work.

Docs about Mach-O:

* https://github.com/kpwn/iOSRE/blob/master/wiki/Mach-O.md
* http://llvm.org/doxygen/Support_2MachO_8h_source.html (5.0.0.svn)
* https://lowlevelbits.org/parsing-mach-o-files/
* https://github.com/AlexDenisov/segment_dumper/blob/master/main.c

Docs about ELF:

* https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

__END__

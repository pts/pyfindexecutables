#!/bin/sh
# by pts@fazekas.hu at Sun Sep  3 10:24:13 CEST 2017

""":" # findexecutables.py: Extracts executables from fat executables.

type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && exec python2.5 -- "$0" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && exec python2.4 -- "$0" ${1+"$@"}
exec python -- ${1+"$@"}; exit 1

This is free software, GNU GPL >=2.0. There is NO WARRANTY. Use at your risk.

This script needs Python 2.4, 2.5, 2.6 or 2.7. Python 3.x won't work.
"""

import struct
import sys

MACHO_CPUTYPES = {
    7: 'x86',  # Can be i386 or amd64.
    8: 'mips',
    10: 'mc98000',  # Old Motorola PowerPC.
    12: 'arm',
    14: 'sparc',
    18: 'powerpc',
}

MACHO_CPUSUBTYPES = {
    7: {
        3: 'x86',  # Also '386'.
        4: '486',
        0x84: '486sx',
        5: '586',
        0x16: 'pentpro',
        0x36: 'pentii_m3',
        0x56: 'pentii_m5',
        0x67: 'celeron',
        0x77: 'celeron_mobile',
        0x08: 'pentium_3',
        0x18: 'pentium_3_m',
        0x28: 'pentium_3_xeon',
        0x09: 'pentium_m',
        0x0a: 'pentium_4',
        0x1a: 'pentium_4_m',
        0x0b: 'itanium',
        0x1b: 'itanium_2',
        0x0c: 'xeon',
        0x1c: 'xeon_mp',
        8: 'x86_64_h',
    },
    8: {
        0: 'mips',
    },
    10: {
        0: 'mc98000',
        1: 'mc98601',
    },
    12: {
        0: 'arm',
        5: 'v4t',
        6: 'v6',
        7: 'v5',
        8: 'xscale',
        9: 'v7',
        10: 'v7f',
        11: 'v7s',
        12: 'v7k',
        14: 'v6m',
        15: 'v7m',
        16: 'v7em',
    },
    14: {
        0: 'sparc',
    },
    18: {
        0: 'powerpc',
        1: '601',
        2: '602',
        3: '603',
        4: '603e',
        5: '603ev',
        6: '604',
        7: '604e',
        8: '620',
        9: '750',
        10: '7400',
        11: '7450',
        100: '970',
    },
}

ELF_MACHINETYPES = {
    0x00: 'unknown',
    0x02: 'sparc',
    0x03: 'x86',
    0x08: 'mips',
    0x14: 'powerpc',
    0x16: 's390',
    0x28: 'arm',
    0x2a: 'superh',
    0x32: 'ia-64',
    0x3e: 'x86-64',
    0xb7: 'aarch64',
    0xf3: 'risc-v',
}


def yield_executables(f):
  """Yields info about the executable parts of a possibly fat exeutable."""

  f.seek(0, 2)
  file_size = f.tell()
  f.seek(0)

  bits, byte_order, format = False, False, None
  magic = f.read(4)
  if magic == '\xca\xfe\xba\xbe':
    bits, byte_order, format = 32, 'msb-first', 'fat-macho'
  elif magic == '\xbe\xba\xfe\xca':
    bits, byte_order, format = 32, 'lsb-first', 'fat-macho'
  elif magic == '\xca\xfe\xba\xbf':
    bits, byte_order, format = 64, 'msb-first', 'fat-macho'
  elif magic == '\xbf\xba\xfe\xca':
    bits, byte_order, format = 64, 'lsb-first', 'fat-macho'
  elif magic == '\xfe\xed\xfa\xce':
    bits, byte_order, format = 32, 'msb-first', 'macho'
  elif magic == '\xce\xfa\xed\xfe':
    bits, byte_order, format = 32, 'lsb-first', 'macho'
  elif magic == '\xfe\xed\xfa\xcf':
    bits, byte_order, format = 64, 'msb-first', 'macho'
  elif magic == '\xcf\xfa\xed\xfe':
    bits, byte_order, format = 64, 'lsb-first', 'macho'
  elif magic == '\x7fELF':
    format = 'elf'
    data = f.read(16)
    if len(data) != 16:
      raise ValueError('EOF in ELF headers.')
    if ord(data[0]) not in (1, 2):
      raise ValueError('Unexpected ELF bits: %d' % ord(data[0]))
    bits = (0, 32, 64)[ord(data[0])]
    if ord(data[1]) not in (1, 2):
      raise ValueError('Unexpected ELF byte order: %d' % ord(data[1]))
    byte_order = (None, 'lsb-first', 'msb-first')[ord(data[1])]
    sp = '<>'[byte_order == 'msb-first']
    e_type, e_machine = struct.unpack(sp + 'HH', data[12 : 16])
    if e_type != 2:
      raise ValueError('Expected executable, got e_type=%d' % e_type)
    if (e_machine == 0x03 and bits != 32 or
        e_machine in (0x32, 0x3e, 0xb7) and bits != 64):
      raise ValueError(
          'Unexpected e_machine: e_machine=0x%2x bits=%d' % (e_machine, bits))
    if e_machine == 0x3e:
      e_machine = 0x03
    cputype_str = cpusubtype_str = ELF_MACHINETYPES.get(
        e_machine, str(e_machine))
    yield (format, byte_order, bits, cputype_str, cpusubtype_str, 0, file_size)
    # TODO(pts): Get the largest file offset available
    #            from program and section headers, extract that.
  else:
    raise ValueError('Unknown magic: %s' % magic.encode('hex'))
  if format not in ('fat-macho', 'macho', 'elf'):
    # TODO(pts): Add support.
    raise NotImplementedError('Unsupported: format=%s byte_order=%s' %
                              (format, byte_order))
  sp = '<>'[byte_order == 'msb-first']

  machos = []
  if format == 'fat-macho':
    data = f.read(4)
    if len(data) != 4:
      raise ValueError('Unexpected EOF in Mach-O fat header.')
    nfat_arch, = struct.unpack(sp + 'L', data)
    if nfat_arch > 255:  # Unlikely.
      raise ValueError('Too many Mach-O parts in fat Mach-O: %d' % nfat_arch)
    for i in xrange(nfat_arch):
      # The align field (as an exponent of a power of 2) indicates the address
      # boundary where the Mach-O should be aligned (generally, this is a page
      # boundary, 4096).
      if bits == 64:
        data = f.read(32)
        if len(data) != 32:
          raise ValueError('Unexpected EOF in Mach-O fat entry.')
        cputype, cpusubtype, xoffset, xsize, align, reserved = struct.unpack(
            sp + 'LLQQLL', data)
      else:
        data = f.read(20)
        if len(data) != 20:
          raise ValueError('Unexpected EOF in Mach-O fat entry.')
        cputype, cpusubtype, xoffset, xsize, align = struct.unpack(
            sp + 'LLLLL', data)
        reserved = 0
      machos.append((cputype, cpusubtype, xoffset, xsize))
  elif format == 'macho':
    data = f.read(8)
    if len(data) != 8:
      raise ValueError('Unexpected EOF in Mach-O header (first pass)l.')
    cputype, cpusubtype = struct.unpack(sp + 'LL', data)
    machos.append((cputype, cpusubtype, 0, file_size))
  for cputype, cpusubytpe, xoffset, xsize in machos:
    format2 = 'macho'
    if xsize < 28:
      raise ValueError('Mach-O part too short: xsize=%d' % xsize)
    if xoffset + xsize > file_size:
      raise ValueError(
          'Mach-O part too long: xoffset=%d xsize=%d file_size=%d' %
          (xoffset, xsize, file_size))
    bits3 = 32
    if cputype & 0x01000000:
      bits3, cputype = 64, cputype & ~0x01000000
    bits4 = 32
    if cpusubtype & 0x80000000:
      bits4, cpusubtype = 64, cpusubtype & ~0x80000000
    f.seek(xoffset)
    magic2 = f.read(4)
    if len(magic2) != 4:
      raise ValueError('Unexpected EOF in Mach-O magic.')
    if magic2 == '\xfe\xed\xfa\xce':
      bits2, byte_order2 = 32, 'msb-first'
    elif magic2 == '\xce\xfa\xed\xfe':
      bits2, byte_order2 = 32, 'lsb-first'
    elif magic2 == '\xfe\xed\xfa\xcf':
      bits2, byte_order2 = 64, 'msb-first'
    elif magic2 == '\xcf\xfa\xed\xfe':
      bits2, byte_order2 = 64, 'lsb-first'
    else:
      raise ValueError('Unknown Mach-O magic: ' % magic2.encode('hex'))
    sp2 = '<>'[byte_order2 == 'msb-first']

    data = f.read(24)
    if len(data) != 24:
      raise ValueError('Unexpected EOF in Mach-O header.')
    cputype2, cpusubtype2, filetype, ncmds, sizeofcmds, flags = (
        struct.unpack(sp2 + 'LLLLLL', data))
    if filetype != 2:
      raise ValueError('Expected executable, got filetype=%d' % filetype)
    bits5 = 32
    if cputype2 & 0x01000000:
      bits5, cputype2 = 64, cputype2 & ~0x01000000
    bits6 = 32
    if cpusubtype2 & 0x80000000:
      bits6, cpusubtype2 = 64, cpusubtype2 & ~0x80000000
    msgargs = ((bits2, bits3, bits4, bits5, bits6), (cputype, cputype2),
               (cpusubtype, cpusubtype2))
    if not (bits2 == bits3 == bits4 == bits5 == bits6):
      raise ValueError(
          'bits mismatch: bits=%r cputypes=%r cpusubtypes=%r' % msgargs)
    if cputype != cputype2:
      raise ValueError(
          'cputype mismatch: bits=%r cputypes=%r cpusubtypes=%r' % msgargs)
    if cputype == 7:
      if cpusubtype == 3:  # CPU_SUBTYPE_I386_ALL.
        cpusubtype = cpusubtype2
      elif cpusubtype2 == 3:
        cpusubtype2 = cpusubtype
    else:
      if cpusubtype == 0:  # CPU_SUBTYPE_ARM_ALL, CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_SPARC_ALL, CPU_SUBTYPE_POWERPC_ALL.
        cpusubtype = cpusubtype2
      elif cpusubtype2 == 0:
        cpusubtype2 = cpusubtype
    if cpusubtype != cpusubtype2:
      raise ValueError(
          'cpusubtype mismatch: bits=%r cputypes=%r cpusubtypes=%r' % msgargs)
    if cputype in MACHO_CPUTYPES:
      cputype_str = MACHO_CPUTYPES[cputype]
      cpusubtype_str = MACHO_CPUSUBTYPES[cputype].get(cpusubtype, str(cpusubtype))
    else:
      cputype_str, cpusubtype_str = str(cputype), str(cpusubtype)
    yield (format2, byte_order2, bits, cputype_str, cpusubtype_str,
           xoffset, xsize)


def main(argv):
  if len(argv) < 2 or argv[1] == '--help':
    sys.exit('error: usage: %s [--extract] <executable-file> [...]' % argv[0])
  do_extract = False
  if argv[1] == '--extract':
    del argv[1]
    do_extract = True
  for filename in argv[1:]:
    f = open(filename, 'rb')
    try:
      for format, byte_order, bits, cputype, cpusubtype, xoffset, xsize in (
          yield_executables(f)):
        sys.stdout.write(
            'format=%s byte_order=%s bits=%d cputype=%s cpusubtype=%s '
            'xoffset=%d xsize=%d f=%s\n' %
             (format, byte_order, bits, cputype, cpusubtype,
              xoffset, xsize, filename))
        sys.stdout.flush()
        if do_extract:
          output_filename = '%s.%d.%s.%s' % (
              filename, bits, cputype, cpusubtype)
          sys.stderr.write('info: extracting to: %s\n' % output_filename)
          sys.stderr.flush()
          of = open(output_filename, 'wb')
          try:
            f.seek(xoffset)
            i = 0
            while i < xsize:
              j = min(65536, xsize - i)
              data = f.read(j)
              if len(data) < j:
                raise ValueError('Unexpected EOF in input file.')
              of.write(data)
              i += j
          finally:
            of.close()
    finally:
      f.close()


if __name__ == '__main__':
  sys.exit(main(sys.argv))

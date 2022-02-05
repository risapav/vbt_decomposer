#!/usr/bin/python

import struct

# header signatures
MAGIC_VBT = b'$VBT'
MAGIC_BDB = b'BIOS_DATA_BLOCK'

# struct vbt_header - VBT Header structure
vbt_header_fmt = (
  "<"
  "20s" # @signature:		VBT signature, always starts with "$VBT"
  "H"   # @version:		Version of this structure
  "H"   # @header_size:	Size of this structure
  "H"   # @vbt_size:		Size of VBT (VBT Header, BDB Header and data blocks)
  "B"   # @vbt_checksum:	Checksum
  "B"   # @reserved0:		Reserved
  "L"   # @bdb_offset:		Offset of &struct bdb_header from beginning of VBT
  "4L"  # @aim_offset:		Offsets of add-in data blocks from beginning of VBT
)

 # struct bdb_header - BDB Header structure
bdb_header_fmt = (
  "<"  
  "16s" # @signature:		BDB signature "BIOS_DATA_BLOCK"
  "H"   # @version:		Version of the data block definitions
  "H"   # @header_size:	Size of this structure
  "H"   # @bdb_size:		Size of BDB (BDB Header and data blocks)
)

 # struct bdb_block - BDB block structure
bdb_block_fmt = (
  "<"  
  "B"   # @id:		BDB id
  "H"   # @size:	BDB size
)

# vbt size, sum
sz_cs_fmt = (
  "<"
  "H"   # @vbt_size:		Size of VBT (VBT Header, BDB Header and data blocks)
  "B"   # @vbt_checksum:	Checksum
)

vbt_header_size = struct.calcsize(vbt_header_fmt)
bdb_header_size = struct.calcsize(bdb_header_fmt)
bdb_block_size = struct.calcsize(bdb_block_fmt)

s_vbt_h = struct.Struct(vbt_header_fmt)
s_dbd_h = struct.Struct(bdb_header_fmt)
s_bdb_b = struct.Struct(bdb_block_fmt)
sz_cs = struct.Struct(sz_cs_fmt)

vbt_header_unpack = s_vbt_h.unpack_from
bdb_header_unpack = s_dbd_h.unpack_from
bdb_block_unpack = s_bdb_b.unpack_from

	
	
	
	
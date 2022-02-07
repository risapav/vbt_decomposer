#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

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

def check_VBT_header(data):
  if data[0][0:4] != MAGIC_VBT: 
    return 1  #error
  return 0    #success

def check_BDB_header(data):
  if data[0][0:15] != MAGIC_BDB:
    return 1  #error
  return 0    #success
	
def compute_crc8_atm(datagram, initial_value=0):
  crc = initial_value
  # Iterate bytes in data
  for byte in datagram:
    # Iterate bits in byte
    for _ in range(0, 8):
      if (crc >> 7) ^ (byte & 0x01):
        crc = ((crc << 1) ^ 0x07) & 0xFF
      else:
        crc = (crc << 1) & 0xFF
      # Shift to next bit
      byte = byte >> 1
  return crc
	
def crc8(datagram, icrc = 0):
  # Iterate bytes in data
  for byte in datagram:
    crc = icrc ^ byte
    for _ in range(8):
      crc <<= 1
      if crc & 0x0100:
        crc ^= 0x07
      crc &= 0xFF
  return crc

def crc(filename, csum = 0):
  try:
    index = 0
    crc8 = csum
    with open(filename, "rb") as f:
      content = f.read() 
      for byte in reversed(content):
        crc8 = ( crc8 + byte ) & 0xFF
        index += 1
        if crc8 == 58 or (0x100 - crc8) == 58:
          print("{} {} {}", crc8, index,  (0x100 - crc8) )
      crc8 = 0x100 - crc8
      print("{} {} {}", crc8, index,  (0x100 - crc8) )
  except FileNotFoundError:
    msg = "Sorry, the file "+ filename + " does not exist."
    print(msg) 
  return crc8 & 0xFF

#/**
#This function will update the VBT checksum.
#@param[in out] VbtPtr - Pointer to VBT table
#@retval none
#**/
#VOID
#UpdateVbtChecksum(
#  VBT_TABLE_DATA *VbtPtr
#  )
#{
#  UINT8           Checksum;
#  UINT8           *VbtStartAddress;
#  UINT8           *VbtEndAddress;
#
#  VbtStartAddress = (UINT8 *)(UINTN)VbtPtr;
#  VbtEndAddress = VbtStartAddress + (VbtPtr->VbtHeader.Table_Size);

#  Checksum = 0;

#  //
#  // Compute the checksum
#  //
#  while (VbtStartAddress != VbtEndAddress) {
#    Checksum = Checksum + (*VbtStartAddress);
#    VbtStartAddress = VbtStartAddress + 1;
#  }
#  Checksum = Checksum - VbtPtr->VbtHeader.Checksum;
#  Checksum = (UINT8)(0x100 - Checksum);

 # //
 # // Update the checksum
 # //
 # VbtPtr->VbtHeader.Checksum = Checksum;

#}
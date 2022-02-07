#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

import vbt_tables as VBT

import sys
import zlib
import json
import binascii

def decompose(filename):
    records = []
    filesize = 0 
    csum = 0  
    try:
        with open(filename, "rb") as f:
            # VBT filesize
            f.seek(0,2)
            filesize = f.tell()
            # move to start of file
            f.seek(0,0)

            ################################
            # VBT header should be the first
            data_p = f.read(VBT.vbt_header_size)
            if not data_p: 
                print ("nothing to do")
                exit(1)
            filesize -= VBT.vbt_header_size
           
            data_u = VBT.vbt_header_unpack(data_p)
            if VBT.check_VBT_header(data_u):
                print ("nie je VBT súbor")
                exit(1)
            records.append( str(data_u) )
            
            ################################
            # BDB header should be the second
            data_p = f.read(VBT.bdb_header_size)
            if not data_p: 
                print ("nothing to do")
                exit(1)     
            filesize -= VBT.bdb_header_size

            data_u = VBT.bdb_header_unpack(data_p)
            if VBT.check_BDB_header(data_u) :
                print ("chyba v BDB zázname")
                exit(1)
            records.append(str(data_u))
            sig, ver, h_size, size = VBT.bdb_header_unpack(data_p)               

            ################################
            # BDB blocks
            while True:
                filesize -= VBT.bdb_block_size
                if filesize >= 0 :
                    data_p = f.read(VBT.bdb_block_size)
                    if not data_p: 
                        break
                    id, size = VBT.bdb_block_unpack(data_p)
                    filesize -= size
                    if filesize >= 0 :
                        data_p = f.read(size)
                    else:
                        break
                    #records.append((id, size, str(binascii.hexlify(data_p))))
                    records.append(str((id, size, binascii.hexlify(data_p))))
                else:
                    break
    except FileNotFoundError:
        msg = "Sorry, the file "+ filename + " does not exist."
        print(msg) 
        
    try:
        # create json file
        with open(filename + ".json", "w") as of:
            of.write(json.dumps(records, sort_keys = False, ensure_ascii=True, indent = 2))
    except:
        msg = "Sorry, the file " + filename + ".json" + " is not writtable."
        print(msg) 

def compose(filename):
    filesize = 0  
    csum = 0
    try: 
        # load json file
        with open(filename + ".json", "r") as f:
            records = json.load(f)
    except:
        msg = "Sorry, the file " + filename + ".json" + " is not available."
        print(msg) 

    try:
        with open(filename + ".new.vbt", "wb") as of:
            global index
            index = 0
            for record in records:
                ################################
                # VBT header magic
                if index == 0: 
                    data_u = eval(record)
                    if VBT.check_VBT_header(data_u):
                        print ("nie je VBT súbor: " + data_u[0][0:4])
                        break
                    else:
                        data_p = VBT.s_vbt_h.pack(*data_u)
                        filesize += VBT.vbt_header_size
                        of.write(data_p)
  #                      csum = VBT.crc(data_p, csum)
   #                     csum1 = VBT.crc8(data_p, csum1)
                        index += 1
                ################################
                # BDB header magic
                elif index == 1: 
                    data_u = eval(record)
                    if VBT.check_BDB_header(data_u) :
                        print ("chyba v BDB zázname")
                        break
                    else:
                        data_p = VBT.s_dbd_h.pack(*data_u)
                        filesize += VBT.bdb_header_size
                        of.write(data_p)
    #                    csum = VBT.crc(data_p, csum)
     #                   csum1 = VBT.crc8(data_p, csum1)
                        index += 1
                ################################
                # BDB block magic
                else: 
                    data_u = eval(record)
                    id, size, block = data_u
                    data_p = VBT.s_bdb_b.pack(id, size) + binascii.unhexlify(block)
                    filesize += VBT.bdb_block_size + size
                    of.write(data_p)
  #                  csum = VBT.crc(data_p, csum)
   #                 csum1 = VBT.crc8(data_p, csum1)
                    index += 1

    # update vbt header
            data_u = eval(records[0])
            v_size = data_u[3]
            v_sum = data_u[4]
            csum = csum - v_sum 
            csum = 0x100 - csum 
            csum1 = csum1 - v_sum 
            csum1 = 0x100 - csum1             
            data_p = VBT.sz_cs.pack(v_size, v_sum)
            of.seek(24,0)
            of.write(data_p)
        csum1 = VBT.crc(filename + ".new.vbt")
    except:
        msg = "Sorry, the file " + filename + ".new.vbt" + " is not writable."
        print(msg) 

#
#import argparse

#parser = argparse.ArgumentParser(description='Dump data.vbt file')
#parser.add_argument('-c','--compose',  help='input file is textfile file.json', required=True)
#parser.add_argument('-d','--decompose',  help='input file is binary file.vbt',required=True)
#parser.add_argument('-h','--help', help='usage: blabla', required=False)

def statistic(a_size, a_sum, b_size, b_sum):
    pass

### main code
def main():
    # otvoriť súbor data.vbt
    filename = "old.vbt"
    #filename = "new.vbt"

    decompile = False
    #decompile = True
#    args = parser.parse_args()
#    print(args.echo)
    if decompile:
        decompose(filename)
    else:
        compose(filename)


if __name__ == "__main__":
    main()

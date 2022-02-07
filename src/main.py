#!/usr/bin/env python3
# -*- coding: utf-8 -*- 

import vbt_tables as VBT

import sys
import zlib
import json
import binascii
import pathlib

def usage():
    print ('usage: vbt_decomposer.py -<command> <inputfile>\n\tcommand:')
    print ('\t\t-c assemble file from <inputfile>[.json]')
    print ('\t\t-d disassemble file from <inputfile>[.vbt]')
    print ('\t\t-h help\n')
    print()
    
#def crc(datagram, icrc = 0):
#    # Iterate bytes in data
#    for byte in datagram:
#        crc = icrc ^ byte
#        for _ in range(8):
#            crc <<= 1
#            if crc & 0x0100:
#                crc ^= 0x07
#        crc &= 0xFF
#    return crc

def calc_sum(datagram, csum):
    sum = csum
    # Iterate bytes in data
    for byte in datagram:    
        sum += byte
    return sum & 0xFF

def calc_crc(csum):
    crc = 0x100 - csum 
    return crc & 0xFF
 #   return csum & 0xFF

def statistic(ids, a_size, a_sum, b_size, b_sum):
    print (f"records total:\t{ids}\n")
    print (f"VBT file size:\t{a_size}\t\tcomputed file size:\t{b_size}\n")
    print (f"VBT file sum:\t{a_sum}\t\tcomputed file sum:\t{b_sum}\n")
    print ()

def decompose(filename):
    records = []
    vbt_size = 0
    vbt_sum = 0
    filesize = 0  
    csum = 0
    index = 0
    try:
        binfile = ""
        file_extension = pathlib.Path(filename).suffix
        if file_extension == ".vbt":
            binfile = filename
        else:
            binfile = filename + ".vbt"

        jsonfile = filename + ".json"

        with open(binfile, "rb") as f:

            ################################
            # VBT header should be the first
            data_p = f.read(VBT.vbt_header_size)
            if not data_p: 
                print ("nothing to do")
                return 1  
            filesize += VBT.vbt_header_size
            csum = calc_sum(data_p, csum)
           
            data_u = VBT.vbt_header_unpack(data_p)
            if VBT.check_VBT_header(data_u):
                print ("nie je VBT súbor")
                return 1  
            records.append( str(data_u) )
            index += 1
            vbt_size = data_u[3]
            vbt_sum = data_u[4]
            
            ################################
            # BDB header should be the second
            data_p = f.read(VBT.bdb_header_size)
            if not data_p: 
                print ("nothing to do")
                return 1     
            filesize += VBT.bdb_header_size
            csum = calc_sum(data_p, csum)

            data_u = VBT.bdb_header_unpack(data_p)
            if VBT.check_BDB_header(data_u) :
                print ("chyba v BDB zázname")
                return 1  
            records.append(str(data_u))
            sig, ver, h_size, size = VBT.bdb_header_unpack(data_p)    
            index += 1

            ################################
            # BDB blocks
            while True:
                data_p = f.read(VBT.bdb_block_size)
                if not data_p: 
                    break
                filesize += VBT.bdb_block_size
                csum = calc_sum(data_p, csum)
                id, size = VBT.bdb_block_unpack(data_p)
                data_p = f.read(size)
                if not data_p: 
                    break
                filesize += size
                csum = calc_sum(data_p, csum)
                #records.append((id, size, str(binascii.hexlify(data_p))))
                records.append(str((id, size, binascii.hexlify(data_p))))
                index += 1
            
        # prepare statistics
        statistic(index, vbt_size, vbt_sum, filesize, calc_crc(csum))
    except FileNotFoundError:
        msg = "Sorry, the file "+ binfile + " does not exist."
        print(msg) 
        return 1
        
    try:
        # create json file
        with open(jsonfile, "w") as of:
            of.write(json.dumps(records, sort_keys = False, ensure_ascii=True, indent = 2))
    except:
        msg = "Sorry, the file " + jsonfile + " is not writtable."
        print(msg) 
        return 1
    return 0

def compose(filename):
    vbt_size = 0
    vbt_sum = 0
    filesize = 0  
    csum = 1
    index = 0
    try: 
        jsonfile = ""
        # load json file
        file_extension = pathlib.Path(filename).suffix
        if file_extension == ".json":
            jsonfile = filename
        else:
            jsonfile = filename + ".json"

        with open(jsonfile, "r") as f:
            records = json.load(f)
    except:
        msg = "Sorry, the file " + jsonfile + " is not available."
        print(msg) 
        return 1

    try:
        binfile = filename + ".new.vbt"
        with open(binfile, "wb") as of:
            for record in records:
                ################################
                # VBT header magic
                if index == 0: 
                    data_u = eval(record)
                    if VBT.check_VBT_header(data_u):
                        print ("nie je VBT súbor: " + data_u[0][0:4])
                        break
                    else:
                        vbt_size = data_u[3]
                        vbt_sum = data_u[4]

                    #    idx = 4
                    #    data_u = data_u[:idx] + (0,) + data_u[idx + 1:]
                        #data_u[4] = 0                       

                        data_p = VBT.s_vbt_h.pack(*data_u)                        
                        of.write(data_p)
                        filesize += VBT.vbt_header_size
                        csum = calc_sum(data_p, csum)
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
                        of.write(data_p)
                        filesize += VBT.bdb_header_size
                        csum = calc_sum(data_p, csum)
                    index += 1
                ################################
                # BDB block magic
                else: 
                    data_u = eval(record)
                    id, size, block = data_u
                    data_p = VBT.s_bdb_b.pack(id, size) + binascii.unhexlify(block)
                    of.write(data_p)
                    filesize += VBT.bdb_block_size + size
                    csum = calc_sum(data_p, csum)
                    index += 1
                    
    # prepare statistics
            data_u = eval(records[0])
            v_size = data_u[3]
            v_sum = data_u[4]
            statistic(index, vbt_size, vbt_sum, filesize, calc_crc(csum))
    # update vbt header        
            data_p = VBT.sz_cs.pack(v_size, v_sum)
            of.seek(24,0)
            of.write(data_p)
    except:
        msg = "Sorry, the file " + binfile + " is not writable."
        print(msg) 
    return 0


import getopt
### main code
def main(argv):
    filename = ''
    # otvoriť súbor data.vbt
    filename = "old.vbt"
    #filename = "new.vbt"    

    try:
        opts, args = getopt.getopt(argv, "h:c:d:", "<inputfile>")
    except getopt.GetoptError:
        usage()
        return 2

    if not opts:
        usage()
        return 2

    for opt, arg in opts:
        if opt in ["-c"]:
            filename = arg
            return compose(filename)
        elif opt in ["-d"]:
            filename = arg
            return decompose(filename)
        else:
            usage()
            return 2        
        

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

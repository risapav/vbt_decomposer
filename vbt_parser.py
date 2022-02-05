#!/usr/bin/python

import vbt_tables

import sys
import zlib
import json
import binascii

# otvoriť súbor data.vbt
filename = "old.vbt"
#filename = "new.vbt"

decompile = False
#decompile = True

filesize = 0        # computed filesize

if decompile: # decompile

    results = []
    with open(filename, "rb") as f:
        # vbt filesize
        f.seek(0,2)
        filesize = f.tell()
        # move to start of file
        f.seek(0,0)

        # vbt header
        data_p = f.read(vbt_tables.vbt_header_size)
        if not data_p: 
            print ("nothing to do")
            exit(1)
        filesize -= vbt_tables.vbt_header_size
        data_u = vbt_tables.vbt_header_unpack(data_p)
        if data_u[0][0:4] != vbt_tables.MAGIC_VBT :
            print ("nie je VBT súbor")
            exit(1)
        results.append(str(data_u) )

        # bdb header
        data_p = f.read(vbt_tables.bdb_header_size)
        if not data_p: 
            print ("nothing to do")
            exit(1)        
        filesize -= vbt_tables.bdb_header_size
        sig, ver, h_size, size = vbt_tables.bdb_header_unpack(data_p)   
        data_u = vbt_tables.bdb_header_unpack(data_p)
        if sig[0:15] != vbt_tables.MAGIC_BDB :
            print ("chyba v BDB zázname")
            exit(1)
        results.append(str(data_u))

        # bdb blocks
        while True:
            filesize -= vbt_tables.bdb_block_size
            if filesize >= 0 :
                data_p = f.read(vbt_tables.bdb_block_size)
                if not data_p: 
                    break
                id, size = vbt_tables.bdb_block_unpack(data_p)
                filesize -= size
                if filesize >= 0 :
                    data_p = f.read(size)
                else:
                    break
                results.append((id, size, str(binascii.hexlify(data_p))))
            else:
                break
    f.close()

    # create json file
    with open(filename+".json", "w") as of:
        of.write(json.dumps(results, sort_keys = False, ensure_ascii=True, indent = 2))
    of.close()   

else: # compile

    # load json file
    with open(filename+".json", "r") as f:
        json_data = json.load(f)
    f.close

    with open(filename+".new.vbt", "wb") as of:
        global i
        i = 0
        for str in json_data:
            if i == 0: #check for $VBT header magic
                data_u = eval(str)
                if data_u[0][0:4] != vbt_tables.MAGIC_VBT :
                    print ("nie je VBT súbor: "+data_u[0][0:4])
                    break
                else:
                    data_p = vbt_tables.s_vbt_h.pack(*data_u)
                    filesize += vbt_tables.vbt_header_size
                    of.write(data_p)
                    i += 1
                    continue

            if i == 1: #check for DBD header magic
                data_u = eval(str)
                if data_u[0][0:15] != vbt_tables.MAGIC_BDB :
                    print ("chyba v BDB zázname")
                    break
                else:
                    data_p = vbt_tables.s_dbd_h.pack(*data_u)
                    filesize += vbt_tables.bdb_header_size
                    of.write(data_p)
                    i += 1
                    continue

            # DBD block magic
            data_u = str
            id, size, block = data_u
            data_p = vbt_tables.s_bdb_b.pack(id, size)
            filesize += vbt_tables.bdb_block_size
            of.write(data_p)
            
            data_p = binascii.unhexlify(eval(block))
            filesize += size
            of.write(data_p)
            i += 1

# update vbt header
        data_u = eval(json_data[0])
        v_size = filesize # data_u[3]
        v_sum = data_u[4]
        data_p = vbt_tables.sz_cs.pack(v_size, v_sum)
        of.seek(24,0)
        of.write(data_p)

        of.close()

exit(0)

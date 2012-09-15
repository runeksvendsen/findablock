from deserialize import *
from BCDataStream import *
from base58 import *
import json
import subprocess
import struct
import Crypto.Hash.SHA256 as sha256
import binascii
import math

coinbase = "Created with this runeks' awesome Python script"
test_generation_address = "1L4fyJqCy5uLmoMo4cG74TaTvgtUwwSHJx"
getmemorypool_command = "bitcoind getmemorypool"

def get_merkle_parents(data):
   hashes = []
   if len(data) >= 2:
      for a in range(int(math.ceil(float(len(data))/2))):
         if (a+1)*2 <= len(data):
            hashes.append( dsha256(data[(a*2)] + data[(a*2)+1]) )
         else:
            hashes.append( dsha256(data[(a*2)] + data[(a*2)]) )
      
      if len(data) >= 3:
         hashes = hashes + get_merkle_list(hashes)
      return hashes
   if len(data) == 1:
      #special case if the block only contains a single transaction
      return data

def get_merkle_tree(txs_data):
   hashes = [dsha256(tx) for tx in txs_data]
   return hashes + get_merkle_parents(hashes)
   #hashes = []
   #first add hashes of all the transactions to the list
   #for tx in txs_data:
   #   hashes.append(dsha256(tx))
   #then add the remaining hashes to the list
   #for shash in get_merkle_list(hashes):
   #   hashes.append(shash)
   #return hashes

def get_merkle_root(txs_data):
   return get_merkle_tree(txs_data)[-1]

def reverse_byte_order(data):
   return data[::-1]

def dsha256(data):
   return sha256.new(sha256.new(data).digest()).digest()

def write_gen_TxIn(vds):
   #'prevout_hash'
   vds.write("\x00"*32)
   #'prevout_n'
   vds.write_uint32(4294967295)
   #coinbase/scriptSig
   #first the size
   vds.write_compact_size(len(coinbase))
   #then the data
   vds.write(coinbase)
   #'sequence'
   vds.write_uint32(4294967295)
   return vds

def write_gen_TxOut(vds, coinbasevalue, address):
   #how many bitcoins can we assign to ourself? (bitcoind has calculated this for us, luckily)
   vds.write_int64(coinbasevalue)
   #this is where the scriptPubKey goes (a script that pays out to the address defined by address)
   scriptPubKey = get_scriptPubKey(address)
   #first the length
   vds.write_compact_size(len(scriptPubKey))
   #then data
   vds.write(scriptPubKey)
   return vds

def get_scriptPubKey(address):
   #we want the following script:
   #"OP_DUP OP_HASH160 <160 byte hex hash of address> OP_EQUALVERIFY OP_CHECKSIG"
   address_hash = bc_address_to_hash_160(address)
   #chr(20) is the length of the address_hash (20 bytes or 160 bits)
   return chr(opcodes.OP_DUP) + chr(opcodes.OP_HASH160) + \
      chr(20) + address_hash + chr(opcodes.OP_EQUALVERIFY) + chr(opcodes.OP_CHECKSIG)

def create_generation_tx(address, coinbasevalue):
   #here we start creating the generation transaction
   gen_tx = BCDataStream()
   ##first we write the version number, which is 1
   gen_tx.write_int32(1)
   ##then we write the number of transaction inputs, which is one
   gen_tx.write_compact_size(1)
   ##then we write the actual transaction input data
   gen_tx = write_gen_TxIn(gen_tx)
   ##then we write the number of transaction outputs, which is one
   gen_tx.write_compact_size(1)
   ##then we write the actual transaction output data
   gen_tx = write_gen_TxOut(gen_tx, coinbasevalue, address)
   #locktime
   gen_tx.write_uint32(0)
   return gen_tx.input

def write_block_header(vds, txs_data):
   #d['version'] = vds.read_int32()   
   vds.write_int32(1)
   #d['hashPrev'] = vds.read_bytes(32)
   hashPrev = "000000000000062df05c939dff2dea97e7e130ba4c8fb93b19c71c8be3fe3137"
   vds.write(reverse_byte_order(hashPrev.decode('hex')))
   #d['hashMerkleRoot'] = vds.read_bytes(32)
   vds.write(get_merkle_root(txs_data))
   #d['nTime'] = vds.read_uint32()
   vds.write_uint32(1347560713)
   #d['nBits'] = vds.read_uint32()
   vds.write_uint32(436615736)
   #d['nNonce'] = vds.read_uint32()
   vds.write_uint32(1766396702)
   #tx_count
   vds.write_compact_size(len(txs_data))
   return vds

def write_block(vds, txs_data):
   vds = write_block_header(vds, txs_data)
   for tx in txs_data:
      vds.write(tx)
   return vds

def main():
   #first we get the data from the getmemorypool command
   res = subprocess.Popen(getmemorypool_command.split(), stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
   
   if res[0] == "error: couldn't connect to server\n":
      print "Error:\tCouldn't connect to a running bitcoin instance.\n\tEither bitcoin isn't running, or you haven't configured it\n\tto accept connections via RPC in bitcoin.conf"
      return -1
   obj = json.loads(res[0])

   #insert the generation transaction as the first item of the 'transactions' list
   obj['transactions'].insert(0,create_generation_tx(test_generation_address, obj['coinbasevalue']).encode('hex'))

   txs_data = []
   for tx in obj['transactions']:
      txs_data.append(tx.decode('hex'))

   test = BCDataStream()
   test = write_block(test, txs_data)

   d = parse_Block(test)
   block_string = deserialize_Block(d)
   
   print "Block height: <dunno>"
   print "BLOCK "+dsha256(test.input[0:80])[::-1].encode('hex_codec')
   print "Next block: <dunno either>"
   print block_string

def test():
   f = open("/home/rune/Desktop/hex_tx.txt")
   data = f.read()

   txs_data = []
   for tx in data[0:-1].split('\n'):
      txs_data.append(tx.decode('hex'))

   test = BCDataStream()
   test = write_block(test, txs_data)

   d = parse_Block(test)
   block_string = deserialize_Block(d)
   
   print "Block height: <dunno>"
   print "BLOCK "+dsha256(test.input[0:80])[::-1].encode('hex_codec')
   print "Next block: <dunno either>"
   print block_string

if __name__ == '__main__':
    main()

import sys, os

os.getcwd()

sys.path.insert(0, '/home/rune/findablock/bitcointools')
sys.path.insert(0, '/home/rune/Programming/bitcointools')

#from deserialize import *
from deserialize import opcodes
from BCDataStream import BCDataStream
#from base58 import *
from base58 import bc_address_to_hash_160
import json
import subprocess
import struct
import Crypto.Hash.SHA256 as sha256
import binascii
import math

coinbase = "Created with runeks' awesome Python script."
test_generation_address = "1L4fyJqCy5uLmoMo4cG74TaTvgtUwwSHJx"
getmemorypool_command = "bitcoind getblocktemplate"

def get_merkle_parents(data):
   hashes = []
   if len(data) >= 2:
      for a in range(int(math.ceil(float(len(data))/2))):
         if (a+1)*2 <= len(data):
            hashes.append( dsha256(data[(a*2)] + data[(a*2)+1]) )
         else:
            hashes.append( dsha256(data[(a*2)] + data[(a*2)]) )
      
      if len(data) >= 3:
         hashes = hashes + get_merkle_parents(hashes)
      return hashes
   if len(data) == 1:
      #special case if the block only contains a single transaction
      #(list in get_merkle_tree already contains the transaction hash)
      return []

def get_merkle_tree(txs_data):
   hashes = [dsha256(tx) for tx in txs_data]
   return hashes + get_merkle_parents(hashes)

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

def get_block(address):
   #returns dict containing data for a block where the generation address is set to <address>

   #first we get the data from the getmemorypool command
   res = subprocess.Popen(getmemorypool_command.split(), stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
   
   if res[0] == "error: couldn't connect to server\n":
      print "Error:\tCouldn't connect to a running bitcoin instance.\n\tEither bitcoin isn't running, or you haven't configured it\n\tto accept connections via RPC in bitcoin.conf"
      return "error: couldn't connect to server"
   try:
      obj = json.loads(res[0])
   except ValueError:
      print "Error: couldn't decode response from bitcoind.\n\tResponse: '%s'" % res[0].rstrip('\n')
      return -1
      

   #insert the generation transaction as the first item of the 'transactions' list
   obj['transactions'].insert(0,
                                 {
                                    "data" : create_generation_tx(address, obj['coinbasevalue']).encode('hex'),
                                 }
                              )

   #now we return a JSON string that contains all the necessary field that need to be published to the network
   return {
     "ver":obj['version'],
     "prev_block":str(obj['previousblockhash']),
     "mrkl_root":reverse_byte_order(get_merkle_root([tx_hex['data'].decode('hex') for tx_hex in obj['transactions']])).encode('hex'),
     "time":obj['curtime'],
     "bits":str(obj['bits']),
     "nonce":0,
     "n_tx":len(obj['transactions']),
     "tx":obj['transactions']
   }

def blockheader_test():
   vds = BCDataStream();

   #d['version'] = vds.read_int32()   
   vds.write_int32(1)
   #d['hashPrev'] = vds.read_bytes(32)
   hashPrev = "00000000000003d239b25d8b3863a5335f2348ed0902ae0824114ae787a14e12"
   vds.write(reverse_byte_order(hashPrev.decode('hex')))
   #vds.write(hashPrev.decode('hex'))
   #d['hashMerkleRoot'] = vds.read_bytes(32)
   #vds.write(get_merkle_root(txs_data))
   vds.write(reverse_byte_order("c19e730f70723ffe27e09d3eb1320bd0098f10d86ef040d27c1a771bcbacf185".decode('hex')))
   #d['nTime'] = vds.read_uint32()
   vds.write_uint32(1347781393)
   #d['nBits'] = vds.read_uint32()
   vds.write_uint32(436615736)
   #d['nNonce'] = vds.read_uint32()
   vds.write_uint32(976697981)

   print vds.input[0:80].encode('hex')
   print dsha256(vds.input[0:80])[::-1].encode('hex_codec')

def block_send_test():
   #first we get the data from the getmemorypool command
   res = subprocess.Popen(getmemorypool_command.split(), stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
   
   if res[0] == "error: couldn't connect to server\n":
      print "Error:\tCouldn't connect to a running bitcoin instance.\n\tEither bitcoin isn't running, or you haven't configured it\n\tto accept connections via RPC in bitcoin.conf"
      return "error: couldn't connect to server"
   obj = json.loads(res[0])

   #insert the generation transaction as the first item of the 'transactions' list
   obj['transactions'].insert(0,create_generation_tx(address, obj['coinbasevalue']).encode('hex'))

   #now we return a dictionaty that contains all the necessary fields that need to be published to the network
   return {
     "ver":obj['version'],
     "prev_block":str(obj['previousblockhash']),
     "mrkl_root":reverse_byte_order(get_merkle_root([tx_hex.decode('hex') for tx_hex in obj['transactions']])).encode('hex'),
     "time":obj['time'],
     "bits":str(obj['bits']),
     "nonce":0,
     "n_tx":len(obj['transactions']),
     "tx":obj['transactions']
   }

def test():
   #these are the transactions, in hex, from block 000000000000034de9c9a67fe15517e8ab93df99f406ab239478714fb825b969
   txs_hex = ["01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0f04f0235250025203062f503253482fffffffff0110dd0f2a010000002321022b48c2917589779a98c79633a9bd965bcfb5f2f2a53a23a615267bf4fc782bb1ac00000000",
"0100000001310f2078d09e5aa169288cae243b6cbba0b4ef076cab57787d47b2b02a9d2a4d000000006b483045022071dd72c20dd170bab6673ff4833b3d1346ef477b7533357b0e5cac71dd03ba52022100eb451aa2fbb9f16df4afd9a35e6c3411bcc1266a0bd7f1e6b0c5657ae62dc9250121023ffba696452d2da449760566c875904b74e30d76a856d7fc249b355fba433b8fffffffff0276faf16fe90200001976a914464e47fabc38df1e76a4bbfb6cb9e6c9aa55747288ac40fbbd0b000000001976a9148d4c37dffe4daee36df84742835b3bfb9dd634af88ac00000000",
"010000000409da40c9505356a12e75b7a44b51d55d8604863f0bb4d0c0026abba69d496e22010000008b483045022075e6af569f950b01d0db8de53a872a6744ba08ca01649bb5eee3dd98450e3afe022100f36d65d98c0f3f8579742f16d9bff78a632355d73ed4eb435f801103169ba6eb01410486a05f9ed027d052e7bce04ee647f7da75228aad91bc7e906d1190772753885f86afed6053e336bac6382b254ca9e588e8623853674fdc20c16c08d7a54caf5ffffffffff4f94dc4fd0f11c24070e53a54e048a4ac9357a02a9ede247f4230f63b236dd0010000008b48304502201d11b5fe0bdf3cc6f58bc9ef00de439d56967732def9fe68fad1da278ef0e45d022100c485f6bab28d7a163ce81528d3c21a6da2c3657774a38dcab892905a82a6fb5801410484ca7fce4877183945babf4a230efcf8cf97e8bebcb748ec9e1bd87cb0c38acf8b6246c3749bc482314c5f265fadd879185ec64a367f7a82949d5392bdf122d9fffffffff428e34bbd7c31df30e3f47d7c3357c38e7046f30e5c148320c0ac1182b9a28e000000008c493046022100d18548db84e182fa2666daae4ed65660e5ca590098a070862088b83e3e3b4289022100d3b8ff0f66a2fc6534ceb44e52e96266533665810bf62fd52f48c8ceee998ff4014104576853b82bb8385ab7d420dd434d5a12f4d3cd17039c927e82ec8218693458f264eb7ec9883950d108470fa3e16e556a0ae64a1b7ca61f821a69b4aa9c4cbea7ffffffff218925217127b2542c3c8867fd88edc37ef2c8b53d566f843fe080d0ef739257000000008c493046022100ddd939a777b21b9a7f06a1c4fa0d0b602b9282e5b97f26ab37aeb4dc1dbf0285022100b6f81511f39f37987a50693f354f042f01eaaf20c31c1b29a401f1c5bfeeeb3b014104f5967455634a5eaf08635b621277a737d2921d40def9252284a5038924db44b378e1704ecb8913a14a3dcf6ae4f63434be2604bfb79e9c0a9cd2766d8e944268ffffffff020045f254050000001976a914c0117dc710c51088de5847d4c920a2dbdff5d7fb88acffdb11bf090000001976a914b6058a5ed88a0af862dfbdd8ea02e1d341c28c0b88ac00000000",
"01000000022a7f34dab20bd9a475ba523464018f3d11c42369760ecd6c8f893904f4f4b04e000000008b4830450221009156bfbc618e1e51b3bf1455a4b5abc4d9cbc4fa5454c49d7843c8508b57956002201718f7709cf9ab4e3ab065d3989d50a0ed1ec9435cd7b2a8c98efebf3fa64846014104606bf18bd8b5994b1e37ce13e7eed33e8508234a40d8795cfa6fe1f875c7e7eea13d31dc6fc77d2cc02880a9848d1573005d246a7a215b6b1ef48f7296a9d0b3ffffffffb32f923d8115660c83cd520ff80b1070eaf5accaebfd7d1b2928527a96250ceb020000008b483045022008733e7eab0a53f2ac9e3979829dee7f40d6d5a26efce3f3798c41f784ae12cf022100ff71c085c8ad9b6124593eb32489eb08fe10d8974a2cebd8bf70c9c438906a82014104e9147ece1c26d3319f6b7b5dbad45ab33429f77668857b9b4f3c7422632d6794a826c8e89791c6a2efb7fc4f2e1b3428a10e470315ff096a547f2e3bf91703e6ffffffff03e0892908000000001976a914b5df3332440430b652f42a817430dda79edc22e988ac3229f767000000001976a914d106dfb4422c85c916be6fe2106385b453faee6988ac3329f767000000001976a9146999a9826e7f5b90e4f4a3ac5fb6cdfa32d3942288ac00000000",
"0100000004208a81732360f8779f1ee13b09d01c4446a6c54f9a406d04352e17fbaf404fa7000000008a4730440220373fda9ec12a3fedf8118d9dc6ab8215145a2afb1578d2e3bbda350fb554c6d302204598f4708ea422d139898f418bfbfaa1a5bda34620d6b024d075294a7e35740a014104f8de68cb550e7bb89c5f03f13121041dc8730e440dd9490adf2f096a5007980cd5f6d0d4a4492535bd98fa54f4ea801f19eefca0633dd590680e22654ca0458effffffffba9812e1db53e0619f1b3673b64c9c595c5b55cb4b949867beef675c0356fb0e010000008a473044022024c03e91dd902a506d17ed570c18567ae7e4b9d7f8d9cb625a43ea35ea18e11302205d8c97c47eb9adf075846a56173929279ab4bd7c0c36dfe8ae06f646a2fbad8e014104caa99331e24ec8be223d3b792c58c32c33a2ad26a33d454d16525c5bfba5f5eeeca713031f8ff1daaf39d00918f0a328272f9024f77961ccb9267674eb08d919ffffffff8ca34573069c7f5947a6b414ea5b6519688dccc7a6591cc26557d455b5e86f58000000008b48304502200db6ba0762062b5720b9ca06d09ae10ddcf63ae4baeaa79cb7795d20439b36b30221009d3cf841536511930f48a0dd6a16d38a0f9b810d69980ffc780397a9a7400bd8014104f8de68cb550e7bb89c5f03f13121041dc8730e440dd9490adf2f096a5007980cd5f6d0d4a4492535bd98fa54f4ea801f19eefca0633dd590680e22654ca0458effffffffffc41dc8f26dba8deb3a787a48883ee6b59f6969e9ba1acd6172b57742c9ff0d010000008b48304502206a6809aba5613f2510e00b71ff68d9acaa15a3be916d9829262f85f664d0351b0221009835f539af24748e720a179bd409dd745c4ddaf9fc5cff34b92cea3cf28adb0d014104caa99331e24ec8be223d3b792c58c32c33a2ad26a33d454d16525c5bfba5f5eeeca713031f8ff1daaf39d00918f0a328272f9024f77961ccb9267674eb08d919ffffffff0240420f00000000001976a9143cb7eb73e37daddd70fc5d6f3ae56bf8495a34a688ac00ca9a3b000000001976a914c6f8966efa4bb0003bf451839390e8eec511004688ac00000000",
"0100000002ea699723f6886ead422b8630c0bcfeb799a0224ac56da3381c4a0d40d3c98729010000008c493046022100db2fb05f5bab98a1921f9fd51b6cdecc310161799a07acc17ddf7dea9708b3cb022100d13edfb14240e89f1d78f7e894db1175d00df0a6dee34612385951c619df03150141048cc0b94178715f03ed3d0bceb368191d0fdd7fc16d806567f6f2c45aecafb8f53e5ef849564072189b9b4f8bfe1564da776567ba359cfb0c05e839bcf65371abffffffff35dcdbdb53a262c5cd05ded921071c3ac95b5462fe0e9f267391f31efae7d19f010000008b483045022040cbe0e1c84b95a9b26ea85f02b7f487e65e64f91a1d9517c7d49420afa7ea86022100e9a5b3ea4e960a2dfb4f9edd31aa13018a427d96511b2e62a34e5a75634b0a6e014104e9147ece1c26d3319f6b7b5dbad45ab33429f77668857b9b4f3c7422632d6794a826c8e89791c6a2efb7fc4f2e1b3428a10e470315ff096a547f2e3bf91703e6ffffffff02fc192d00000000001976a9148ff110932df33b1d184787dc1fd40d71c06dfb3788ac94038676000000001976a914d106dfb4422c85c916be6fe2106385b453faee6988ac00000000",
"010000000250c82f0e1b42e297bc20aa2cf58ed5980f109d4af893cbeeca5d3255f5200a1f010000008b483045022100d6c28f28a858c7491ed3d5a5c0708cbc0d188bd454332dca64a29a3cd99b504e02201a09c7c853a57d2f5af2340f5e089520e5eeb05d1d31f3485d936226a907c128014104606bf18bd8b5994b1e37ce13e7eed33e8508234a40d8795cfa6fe1f875c7e7eea13d31dc6fc77d2cc02880a9848d1573005d246a7a215b6b1ef48f7296a9d0b3ffffffff1b877fd2e704de7c2f8700867bf8de310e92974a4bd932fcf53c546999315b16010000008c493046022100b54cc58da7e11a61d7fe6d2a373334eefab27e1d5eb438761dba93f600b157ce022100ee1d4d651832078e6c027639d26046ceab8a71c007b154911a7398f14421e8e4014104807ec4487b6dc32cc7b207aea75f501438305f443962ed50a8a621b168e9d52b45072b264a2c2838e57cb505e148b9759eeec2d1f3698de155bd989a0b11c288ffffffff0238191d00000000001976a914a09c4b7408fc57a7edcc86b1090b5dae00b36f6988acb18ece5c000000001976a914b59cd5a89a456ac7dbcb3a4b54de1df958c3d41288ac00000000",
"01000000015a5b9ce1af00723895fd736d0eecbbfe9a3ffad02bc494581bbab8d09d34d32f000000006c493046022100ed955ba74c6d6ae356ea98cd60d8792fb0db7a145690e844fc75eda906cbeabb0221008f0a74d0270dd6beeac9fa731765b78edaf525899ef56dbc5fd51349f00bf09401210230536f3e2f00be101319398d08327faaef7e30872712c28eb83a9504b067169cffffffff02c081c7b7020000001976a91470e27273dd0e24211f4aed44d4ff974fcb03085f88aca079f13e010000001976a914e968f47e597f93bd6c1205bf95ce64dfa9a5f90088ac00000000"]

   txs_data = []
   for tx_hex in txs_hex:
      txs_data.append(tx_hex.decode('hex'))

   test = BCDataStream()
   test = write_block(test, txs_data)

   d = parse_Block(test)
   block_string = deserialize_Block(d)
   
   print "Block height: <dunno>"
   print "BLOCK "+dsha256(test.input[0:80])[::-1].encode('hex_codec')
   print "Next block: <dunno either>"
   print block_string
   
def get_fakeblock(address):

   res = subprocess.Popen(
                          ("/home/rune/Programming/scripts/bitcoin/findablock/bitcointools/dbdump.py",
                           "--block=190000", "--print-json"),
                           stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()
   
   obj = json.loads(res[0])

   #insert the generation transaction as the first item of the 'transactions' list
   #obj['transactions'].insert(0,create_generation_tx(address, obj['coinbasevalue']).encode('hex'))

   #now we return a JSON string that contains all the necessary field that need to be published to the network
   return {
     "ver":obj['version'],
     "prev_block":str(obj['previousblockhash']),
     "mrkl_root":reverse_byte_order(get_merkle_root([tx_hex.decode('hex') for tx_hex in obj['transactions']])).encode('hex'),
     "time":obj['time'],
     "bits":str(obj['bits']),
     "nonce":obj['nonce'],
     "n_tx":len(obj['transactions']),
     "tx":obj['transactions']
   }

#get_block = get_fakeblock

if __name__ == "__main__":
    #get_fakeblock(test_generation_address)
   print get_block(test_generation_address)

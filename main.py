import hashlib
import random
from ecdsa import SigningKey, SECP256k1
import sha3
from bip32utils import BIP32Key
from web3 import AsyncWeb3
import asyncio

count_dict = {'count': 0}
current_node_index = 0

def generate_entropy(bits):
  bytes_length = bits // 8
  random_bytes = bytearray(bytes_length)
  random.seed()
  for i in range(bytes_length):
    random_bytes[i] = random.randint(0, 255)

  return bytes(random_bytes)

def calculate_checksum(entropy):
  hash_bytes = hashlib.sha256(entropy).digest()
  hash_bits = ''.join(format(byte, '08b') for byte in hash_bytes)
  entropy_bits = ''.join(format(byte, '08b') for byte in entropy)
  checksum_length = len(entropy_bits) // 32

  return hash_bits[:checksum_length]

def generate_mnemonic(bits):
  entropy = generate_entropy(bits)
  checksum = calculate_checksum(entropy)
  mnemonic_length = (bits + len(checksum)) // 11
  binary_str = ''.join(format(byte, '08b') for byte in entropy)
  binary_str += checksum
  mnemonic = ''
  for i in range(mnemonic_length):
    start_index = i * 11
    end_index = (i + 1) * 11
    index = int(binary_str[start_index:end_index], 2)
    mnemonic += WORD_LIST[index] + ' '

  return mnemonic.strip()

def generate_ethereum_key_pair_from_mnemonic(mnemonic):
  seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), b'mnemonic', 2048)
  master_key = BIP32Key.fromEntropy(seed)
  path = [44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0]
  for index in path:
    master_key = master_key.ChildKey(index)
  private_key_wif = master_key.WalletImportFormat()
  private_key_hex = master_key.PrivateKey().hex()

  return private_key_hex, private_key_wif

def generate_ethereum_address(private_key_hex):
  priv = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
  pub = priv.get_verifying_key().to_string()
  keccak = sha3.keccak_256()
  keccak.update(pub)
  address = keccak.hexdigest()[24:]

  return checksum_encode(address), pub.hex()

def checksum_encode(addr_str):
  keccak = sha3.keccak_256()
  out = ''
  addr = addr_str.lower().replace('0x', '')
  keccak.update(addr.encode('ascii'))
  hash_addr = keccak.hexdigest()
  for i, c in enumerate(addr):
    if int(hash_addr[i], 16) >= 8:
      out += c.upper()
    else:
      out += c

  return '0x' + out

def load_list_from_file(filename):
  with open(filename, 'r') as file:
    loaded_list = [line.strip() for line in file.readlines()]
  return loaded_list

async def get_transaction_count(w3, address):
  try:
    transaction_count = await w3.eth.get_transaction_count(address)
    return transaction_count
  except Exception as e:
    return None

async def check_addr(w3, nodes, file_path):
  global current_node_index
  while True:
    try:
      mnemonic = generate_mnemonic(128)
      private_key, _ = generate_ethereum_key_pair_from_mnemonic(mnemonic)
      address, _ = generate_ethereum_address(private_key)
      transaction_count = await get_transaction_count(w3, address)

      if transaction_count is not None:
        count_dict['count'] += 1
        print(f'{count_dict["count"]}.{transaction_count} TX | {address} {mnemonic}')
      if transaction_count is not None and transaction_count !=0:
        with open(file_path, 'a') as file:
          file.write(f'{count_dict["count"]}.{transaction_count} TX | {address} {mnemonic} {private_key}\n')    
      await switch_node(w3, nodes)
      current_node_index = (current_node_index + 1) % len(nodes)
      await asyncio.sleep(0)
    except (ValueError, Exception) as e:
      await asyncio.sleep(0)

async def switch_node(w3, nodes):
  global current_node_index
  for _ in range(len(nodes)):
    try:
      node = nodes[current_node_index]
      w3.provider = AsyncWeb3.AsyncHTTPProvider(node)
      await w3.eth.get_block('latest')
      return
    except Exception as e:
      current_node_index = (current_node_index + 1) % len(nodes)
  await asyncio.sleep(10)

WORD_LIST = load_list_from_file('wordList.txt')

async def main():
  nodes = load_list_from_file('nodes.txt')
  w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(nodes[0]))
  
  num_requests = 50
  file_path = 'results.txt'
  
  await check_addresses(w3, nodes, num_requests, file_path)

async def check_addresses(w3, nodes, num_requests, file_path):
  tasks = [check_addr(w3, nodes, file_path) for _ in range(num_requests)]
  await asyncio.gather(*tasks)

asyncio.run(main())
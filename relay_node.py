import subprocess
import socket
import time
import urllib
import ast
import json
import sys

# Libraries for Cryptography
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
from hashlib import sha256

# Initialization of key-variables

# AES concerning variables
global aes_key
global cipher
flag = 0
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

ping_list = list()
final_list = list()
trace_list = list()

# RSA concerning variables
key_size = 2048
hash = "SHA-256"

# TCP buffer size
buffer_size = 4096

'''
relays_list = ["frapa","kiwi","mango","milo"]
relays_ip_list = ['147.52.19.28','147.52.19.59','147.52.19.55','147.52.19.9']
relays_port_list = [60000,60001,60002,60003]
'''

'''AES CLASS & METHODS'''
class AESCipher:

	def __init__( self, key ):
		self.key = key

	def encrypt( self, raw ):
		raw = pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher_text = AES.new( self.key, AES.MODE_CBC, iv )
		return b64encode( iv + cipher_text.encrypt( raw ) )

	def decrypt( self, enc ):
		enc = b64decode(enc)
		iv = enc[:16]
		cipher_text = AES.new(self.key, AES.MODE_CBC, iv )
		return unpad(cipher_text.decrypt( enc[16:] ))

'''RSA METHODS'''
# Whole Encryption method
def encrypt(plain):
	# Make signature with private key and make the packet
	signature_created = b64encode(sign(plain, private, "SHA-256"))
	# Join strings
	overall_packet = plain + '\n' + signature_created
	# Encrypt packet with public key of the other side
	limitation = 128
	encryption_chunks_created = ([overall_packet[ite:ite + limitation] for ite in range(0, len(overall_packet), limitation)])
	for it in range(0, len(encryption_chunks_created)):
		encryption_chunks_created[it] = public_key_received.encrypt(encryption_chunks_created[it], 32)
	string = json.dumps(str(encryption_chunks_created))
	connection.sendall(string)

# Whole Decryption method
def decrypt(cipher_text):
	# Load encrypted data
	data_loaded = (json.loads(cipher_text))
	# Decrypt cipher text and get plaintext and signature
	decrypted_message_created = make_decryption_chunks(data_loaded, private)
	# Split Cipher text from signature
	(plaintext, signature) = split_plaintext_signature(decrypted_message_created)
	# Check verification output
	verify_signature = verify(plaintext, b64decode(signature), public_key_received)
	return verify_signature,plaintext

# Split the plaintext from the signature
def split_plaintext_signature(decrypt_message):
	plaintext_original = (decrypt_message[0][0:decrypt_message[0].find("\n")])
	signature_original = (decrypt_message[0][decrypt_message[0].find("\n") + 1:len(decrypt_message[0])])
	signature_original += ''.join(decrypt_message[1:len(decrypt_message)])
	return plaintext_original,signature_original

# Chop Encrypted message and decrypt every cipher
def make_decryption_chunks(data_load,key):
	size = data_load.count(",)")
	decrypted_list = list()
	fnl_list = list()
	for j in range(0,size):
		decrypted_list.append(data_load[data_load.find("(") : data_load.find(",)") + 2])
		data_load = data_load.replace(data_load[data_load.find("(") : data_load.find(",)") + 2], '')
		fnl_list.append(key.decrypt(ast.literal_eval(str(decrypted_list[j]))))
	count=0
	index = 0
	for j in range(0, len(fnl_list)):
		if "==" in fnl_list[j]:
			if count==0:
				index = j
			count+=1
	if count>1:
		return fnl_list[0:index+1]
	else:
		return fnl_list

# Create a signature using a key and a hash algorithm
def sign(mess, key, hash_alg="SHA-256"):
	global hash
	hash = hash_alg
	signer = PKCS1_v1_5.new(key)
	if hash == "SHA-512":
		digest = SHA512.new()
	elif hash == "SHA-384":
		digest = SHA384.new()
	elif hash == "SHA-256":
		digest = SHA256.new()
	elif hash == "SHA-1":
		digest = SHA.new()
	else:
		digest = MD5.new()
	digest.update(mess)
	return signer.sign(digest)

# Verify signature method
def verify(mess, signature_name, pub_key):
	signer = PKCS1_v1_5.new(pub_key)
	if hash == "SHA-512":
		digest = SHA512.new()
	elif hash == "SHA-384":
		digest = SHA384.new()
	elif hash == "SHA-256":
		digest = SHA256.new()
	elif hash == "SHA-1":
		digest = SHA.new()
	else:
		digest = MD5.new()
	digest.update(mess)
	return signer.verify(digest, signature_name)

# Create RSA private and public keys
def new_keys(size):
	random_generator = Random.new().read
	key = RSA.generate(size, random_generator)
	private_key, public_key = key, key.publickey()
	return public_key, private_key

'''CALCULATION METHODS'''
# Calculate average RTT
def calculate_rtt(dat):
	relay_list = dat.split(",")
	p = subprocess.check_output(['ping', socket.gethostbyname(relay_list[0]), '-c', relay_list[1]])
	ping_list.append(p.splitlines()[len(p.splitlines()) - 1].split("/")[4])

# Calculate HOPS
def calculate_hops(dat):
	relay_list = dat.split(",")
	p = subprocess.check_output(['traceroute', socket.gethostbyname(relay_list[0])])
	hops = len(p.split('\n')) - 2
	trace_list.append(hops)

# Form the lists
def form_final_list():
	final_list.append(ping_list[0])
	final_list.append(trace_list[0])

# Cleanup
def empty_lists():
	del ping_list[:]
	del trace_list[:]
	del final_list[:]

#Create keys for cryptography
(public, private) = new_keys(key_size)

# Create Socket that its address and port are re-usable
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

'''
# Choose IP and Port based on input
i = 0
k = 0
while i in range(len(relays_list)):
	if relays_list[i] == sys.argv[1]:
		k = i
		i += 1
	else:
		i += 1
'''

s.bind(('',60000))
s.listen(1)

while True:
	# Wait for a connection
	print('waiting for a connection')
	connection, client_address = s.accept()
	try:
		print('connection from', client_address)
		while True:
			data = connection.recv(buffer_size)
			#print('Received {!r}'.format(data))
			#print(cipher.decrypt(data))
			if data:
				if "BEGIN" in data:
					# Receive public key
					public_key_received =  RSA.importKey(data)
					# Send public key to the other side
					connection.sendall(public.exportKey())
				else:
					if flag == 0:
						# Decrypt message with all requirements
						(verify1,text) = decrypt(data)
						if verify1:
							print("VERIFICATION SUCCESSFUL")
							aes_key = text
							connection.sendall("AES key received")
							flag = 1
						else:
							print("Verification wasn't successful.")
					else:
						cipher = AESCipher(aes_key)
						text = cipher.decrypt(data)
						data = text
						if data[0:4] == "http":
							urllib.urlretrieve(data, "download%s" % data[data.rfind('.'):len(data)])
							downloaded_item = "download%s" % data[data.rfind('.'):len(data)]
							end = time.time()
							# Encrypt end time with all requirements
							connection.sendall(cipher.encrypt(str(end)))
							# Send bytes of image
							my_file = open(downloaded_item, 'rb')
							bytes = my_file.read()
							connection.sendall(cipher.encrypt(bytes))
							print 'Image successfully send to server'
							myfile.close()
						else:
							# Make calculations...
							calculate_rtt(data)
							calculate_hops(data)
							form_final_list()
							# Return avg-RTT and number of hops back to client
							msg = ','.join(map(str, final_list))
							# Encrypt message with all requirements
							connection.sendall(cipher.encrypt(msg))
							# Empty lists
							empty_lists()
			else:
				print('no data from', client_address)
				break
	except Exception as e:
		# Sleep for 5 seconds to avoid Connection refused exceptions
		time.sleep(5)
	finally:
		# Clean up the connection
		print("Closing current connection")
		connection.close()
import socket
import sys
import subprocess
import threading
import urllib
import random
import time
import ast
import json
import re

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

# Public keys of relay servers
public_keys_received = list()
# IPs of Relays("147.52.19.28'",etc..)
relay_ip = list()
# Name of Relays(frapa,milo,etc..)
relay_id = list()
# Number of ports of every Relay(60000,etc..)
relay_ports = list()
# Shortcut names of end-servers("google",etc..)
end_shortcut = list()
# Canonical names of end-servers("www.google.com",etc..)
end_id = list()
# Average RTT of direct mode to end-server
rtt_direct_mode_list = list()
# Average RTT of relay mode to end-server
rtt_relay_mode_list = list()
# Sum of averages RTT of relay and end-server
rtt_relay_to_end = list()

rtt_relay_overview = list()
# Number of HOPS to end-server with direct mode
hops_direct_mode_list = list()
# Number of HOPS to relays
hops_relay_mode_list = list()
# Sum of HOPS of direct mode and best relay mode
hops_relay_to_end = list()

hops_relay_overview = list()
# URLS of text file to download
files2download = list()

# AES concerning variables
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]

# RSA concerning variables
key_size = 2048
hash = "SHA-256"

# TCP buffer size
buffer_size = 4096

'''AES CLASS & METHODS'''
class AESCipher:

	def __init__( self, key ):
		self.key = key

	def encrypt( self, raw ):
		raw = pad(raw)
		iv = Random.new().read( AES.block_size )
		cipher = AES.new( self.key, AES.MODE_CBC, iv )
		return b64encode( iv + cipher.encrypt( raw ) )

	def decrypt( self, enc ):
		enc = b64decode(enc)
		iv = enc[:16]
		cipher = AES.new(self.key, AES.MODE_CBC, iv )
		return unpad(cipher.decrypt( enc[16:] ))

'''RSA METHODS'''
# Create RSA private and public keys
def new_keys(size):
	random_generator = Random.new().read
	key = RSA.generate(size, random_generator)
	private_key, public_key_created = key, key.publickey()
	return public_key_created, private_key

# Create a signature using a key and a hash algorithm
def sign(msg, key, hash_alg="SHA-256"):
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
	digest.update(msg)
	return signer.sign(digest)

# Verify signature with specific key
def verify(msg, signature_name, pub_key):
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
	digest.update(msg)
	return signer.verify(digest, signature_name)

# Split the plaintext from the signature
def split_plaintext_signature(decrypt_message):
	plaintext1 = (decrypt_message[0][0:decrypt_message[0].find("\n")])
	signature1 = (decrypt_message[0][decrypt_message[0].find("\n") + 1:len(decrypt_message[0])])
	signature1 += ''.join(decrypt_message[1:len(decrypt_message)])
	return plaintext1,signature1

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

# Whole Encryption method
def encrypt(plain,key):
	# Make signature with private key and make the packet

	signature_created = b64encode(sign(plain, private, "SHA-256"))
	# Join strings
	overall_packet = plain + '\n' + signature_created
	# Encrypt packet with public key of the other side
	limitation = 128
	encryption_chunks_created = ([overall_packet[i:i + limitation] for i in range(0, len(overall_packet), limitation)])
	for i in range(0, len(encryption_chunks_created)):
		encryption_chunks_created[i] = key.encrypt(encryption_chunks_created[i], 32)
	string = json.dumps(str(encryption_chunks_created))
	return string

# Whole Decryption method
def decrypt(cipher,key):
	# Load encrypted data
	data_loaded = (json.loads(cipher))
	# Decrypt cipher text and get plaintext and signature
	decrypted_message_created = make_decryption_chunks(data_loaded, private)
	# Split Cipher text from signature
	(plaintext, signature) = split_plaintext_signature(decrypted_message_created)
	# Check verification output
	verify_signature = verify(plaintext, b64decode(signature), key)
	return verify_signature,plaintext

'''CALCULATION METHODS'''
# Calculate average RTT
def calculate_rtt(ping, ip):
	try:
		p = subprocess.check_output(['ping', ip, '-c', ping])
		return p.splitlines()[len(p.splitlines()) - 1].split("/")[4]
	except Exception as e:
		return None

# Calculate HOPS
def calculate_hops(ip):
	try:
		p = subprocess.check_output(['traceroute', ip])
		hops = len(p.split('\n')) - 2
		return hops
	except Exception as e:
		return None

# Calculate best route
def best_route(rtt_overview, hops_overview, rtt_direct_mode, hops_direct_mode):
	min_rtt = max(rtt_overview) #timi tou min
	index = rtt_overview.index(min_rtt) #thesi tou min
	for i in range(len(rtt_overview)):
		if (rtt_overview[i]>0) and (rtt_overview[i]<min_rtt):
			min_rtt = rtt_overview[i]
			index = i
	# Checking if same RTT occurs then check for HOPS
	for i in range(len(rtt_overview)):
		if rtt_overview[i]>0 and rtt_overview[i]==min_rtt:
			if hops_overview[i] < hops_overview[index]:
				min_rtt = rtt_overview[i]
				index = i
	# If all relays are disconnected
	if rtt_overview[index]==0:
		print 'The best route is the Direct_Mode'
		return -1
	# if relay mode is faster than direct mode
	elif float(rtt_overview[index]) < float(rtt_direct_mode[0]):
		print 'The best route is:',relay_id[index]
		return index
	# if direct mode is faster than relay mode
	elif float(rtt_overview[index]) > float(rtt_direct_mode[0]):
		print 'The best route is the Direct_Mode'
		return -1
	# if RTTs equal between direct and relay mode
	else:
		# if HOPs of relay do not exist or HOPs of direct are less than relays HOPs
		if hops_overview[index] == 0 :
			print 'The best route is the Direct_Mode'
			return -1
		elif hops_overview[index] > int(hops_direct_mode[0]):
			print 'The best route is the Direct_Mode'
			return -1
		# if HOPs of relay less than direct
		elif hops_overview[index] < int(hops_direct_mode[0]):
			print 'The best route is:',relay_id[index]
		# Getting random mode
		else:
			print ("Returning a random route: ")
			rand = random.choice([-1,index])
			if rand != -1:
				print 'Best route is:',relay_id[rand]
			else:
				print 'Best route is the Direct_Mode'
			return rand

'''INPUT COMMAND METHODS'''
# Process text files from input
def process_txt_files(args):
	if len(args) == 5:
		f = open("relay_nodes.txt", "r")
		relays = [w.replace(',', '') for w in f.read().split()]
		k = 0
		for i in range(len(relays)):
			if k == 0:
				relay_id.append(relays[i])
				k+=1
			elif k == 1:
				relay_ip.append(relays[i])
				k+=1
			elif k == 2:
				relay_ports.append(relays[i])
				k=0
		del relays[:]
		f = open("end_servers.txt", "r")
		ends = [w.replace(',', '') for w in f.read().split()]
		f.close()
		for i in range(len(ends)):
			if i % 2 == 1:
				end_shortcut.append(ends[i])
			else:
				end_id.append(ends[i])
		del ends[:]

	else:
		print("Not enough arguments!")

# Ask user for input of server and ping number
def get_input_direct_mode():
	while 1:
		try:
			input1 = raw_input('Enter your input for End Server & number of PINGS: ')
			shortcut = input1[0:re.search("\d",input1).start()]
			shortcut = shortcut.replace(" ","")
			ping = input1[re.search("\d",input1).start()]
			if (shortcut in s for s in end_shortcut):
				return end_id[end_shortcut.index(shortcut)],ping[0]
			else:
				print("End-Server not found!Try again!\n")
		except Exception as e:
			print("Wrong format of message")

# Get URL (if exists) from text file
def get_url():
	f = open("files2download.txt", "r")
	files2download.extend(f.read().split())
	f.close()
	while True:
		input = raw_input('Enter your url: ')
		if input in files2download:
			return input
		else:
			print("URL does not exist!Try again.")

# Check if we can PING and TRACE ROUTE server
def check_ping():
	(direct, number) = get_input_direct_mode()
	while 1:
		if calculate_rtt(number, socket.gethostbyname(direct)) is None or calculate_hops(socket.gethostbyname(direct)) is None:
			print("Cannot access End-server for calculating metrics.")
			(direct, number) = get_input_direct_mode()
		else:
			return direct,number

'''THREADS METHODS & CLASS'''
# Class for everything NOT concerning TCP sockets
class MyThread(threading.Thread):
	def __init__(self, thread_id,ip):
		self.thread_id = thread_id
		self.ip = ip
		threading.Thread.__init__(self)

	def run(self):
		id = self.thread_id
		ip = self.ip
		if id % 2 == 0:
			if id == 0:
				rtt_direct_mode_list.append(calculate_rtt(ping_number, ip))
			else:
				rtt_relay_mode_list.append(calculate_rtt(ping_number, ip))
		else:
			if id == 1:
				hops_direct_mode_list.append(calculate_hops(ip))
			else:
				hops_relay_mode_list.append(calculate_hops(ip))

# Class for TCP socket
class MyThreadTCP(threading.Thread):
	def __init__(self, thread_id,thread_link,thread_ping):
		self.thread_id = thread_id
		self.thread_link = thread_link
		self.thread_ping = thread_ping
		threading.Thread.__init__(self)
	def run(self):
		# Create TCP
		create_sockets(self.thread_link, self.thread_ping)

# Class for TCP getting URL
class MyThreadURL(threading.Thread):
	def __init__(self, thread_id, thread_url):
		self.thread_id = thread_id
		self.thread_url = thread_url
		threading.Thread.__init__(self)
	def run(self):
		# Download file
		file_download(self.thread_url)

# Make list of IPs of every server(end & relay)
def store_ip_threading(ping):
	temp_list = list()
	for l in range(len(relay_id) + 1):
		if l == 0:
			temp_list.append(socket.gethostbyname(ping))
		else:
			temp_list.append(relay_ip[l - 1])
	return temp_list

# Create threads
def create_threads(list_tmp,link,ping):
	thread = list()
	tcp_thread = list()
	url_thread = list()
	j = 0
	k = 0
	for u in range(2 * len(relay_id) + 2):
		if k == 2:
			j += 1
			thread.append(MyThread(u,list_tmp[j]))
			k = 1
		else:
			thread.append(MyThread(u,list_tmp[j]))
			k += 1
	'''
	for y in range(2):
		if y==0:
			tcp_thread.append(MyThreadTCP(y,link,ping))
		else:
			tcp_thread.append(MyThreadURL(y,get_url()))
	'''
	tcp_thread.append(MyThreadTCP(0, link, ping))
	url_thread.append(MyThreadURL(0, get_url()))
	return thread,tcp_thread,url_thread

# Initialize threads
def start_threads(thr,tcp,url):
	for i in range(0, len(thr)):
		thr[i].start()
	# Wait for all threads to complete
	for t in range(0, len(thr)):
		thr[t].join()
	# Threads concerning TCP sockets
	tcp[0].start()
	tcp[0].join()
	#time.sleep(10)
	url[0].start()
	url[0].join()

'''CLEANUP METHODS'''
# Clean threads lists
def empty_lists():
	del threads[:]
	del tmp_list[:]
	del tcp_threads[:]

# Clean all lists concerning all RTT and HOP
def clean_everything():
	del rtt_direct_mode_list[:]
	del rtt_relay_mode_list[:]
	del rtt_relay_to_end[:]
	del rtt_relay_overview[:]
	del hops_direct_mode_list[:]
	del hops_relay_mode_list[:]
	del hops_relay_to_end[:]
	del hops_relay_overview[:]

# URLS of text file to download

'''SOCKET METHODS'''
# Initiate TCP socket connection with Encryption-Decryption
def create_sockets(id,ping_num):
	global public_rec
	for i in range(len(relay_id)):
		# Create socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connect the socket to the port where the server is listening
		#server_address = (relay_ip[i], int(relay_ports[i]))
		server_address = (relay_ip[i], 60000)
		try:
			cipher = AESCipher('mysecretpassword')
			sock.connect(server_address)
			print 'Server:', relay_id[i], 'is ON'
			# Make handshake
			msg = id + "," + str(ping_num)
			sock.sendall(public.exportKey())
			# Receive Keys from relay
			exchange = sock.recv(buffer_size)
			if exchange:
				if "BEGIN" in exchange:
					print("Received RSA public key of %s received successfully"%(relay_id[i]))
					public_rec = (RSA.importKey(exchange))
					public_keys_received.append(public_rec.exportKey())
					sock.sendall(encrypt('mysecretpassword',public_rec))
					response = sock.recv(buffer_size)
					if response == "AES key received":
						print("Exchanged AES key successfully with %s"%(relay_id[i]))
						sock.sendall(cipher.encrypt(msg))
					else:
						print("Didn't exchange AES key.")
				else:
					print("Didn't get RSA key.")
			# Receive decrypted message of RTT and calculation of HOPS
			data = sock.recv(buffer_size)
			if data:
				# Decrypt message with all requirements
				text = cipher.decrypt(data)
				# Relay to end server metrics (RTT and HOPS of current relay)
				rtt_relay_to_end.extend(text.split(","))
				# Put HOPS to the HOPS list of current relay node
				hops_relay_to_end.append(rtt_relay_to_end[-1])
				# Delete HOPS from RTT list of current relay node
				rtt_relay_to_end.pop(-1)
				# Sum of client to relay and relay to end server RTT of current relay
				num = float(rtt_relay_to_end[i]) + float(rtt_relay_mode_list[i])
				# Put sum of RTT to FINAL LIST of current relay
				rtt_relay_overview.append(num)
				# Sum of client to relay and relay to end server HOPS of current relay
				num = int(hops_relay_mode_list[i]) + int((hops_relay_to_end[i]))
				# Put sum of HOPS to FINAL LIST of current relay
				hops_relay_overview.append(num)
			else:
				print ("No data sent by server")
		# If relay server is OFF
		except Exception as e:
			print 'Server:', relay_id[i], 'is OFF!'
			rtt_relay_to_end.append(0)
			hops_relay_to_end.append(0)
			rtt_relay_overview.append(0)
			hops_relay_overview.append(0)
			continue
		finally:
			print('closing socket')
			sock.close()

# Download file whether on direct mode or relay mode
def file_download(url):
	index = best_route(rtt_relay_overview, hops_relay_overview, rtt_direct_mode_list, hops_direct_mode_list)
	if index == -1:
		if ".gif" in url:
			start = time.time()
			urllib.urlretrieve(url,"download.gif")
			end = time.time()
			print("Elapsed time for download is: %f %s." %((end - start),'secs'))
		else:
			start = time.time()
			urllib.urlretrieve(url, "download.png")
			end = time.time()
			print("Elapsed time for download is: %f %s." %((end - start),'secs'))
	else:
		if url in files2download:
			sockets_url(url,index)

# Initiation of TCP handshake for downloading file
def sockets_url(url,index):
	# Create socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Connect the socket to the port where the server is listening
	server_address = (relay_ip[index], 60000)
	sock.connect(server_address)
	try:
		cipher = AESCipher('mysecretpassword')
		start = time.time()
		# Send Encrypted URL with signature
		sock.sendall(cipher.encrypt(url))
		data = sock.recv(buffer_size)
		if data:
			# Decrypt message with all requirements
			text = cipher.decrypt(data)
			end = float(text)
			print("Elapsed time for download is: %f %s." % ((end-start), 'secs'))
		else:
			print("Couldn't retrieve time.")
		bytes = sock.recv(40960000)
		bytes = cipher.decrypt(bytes)
		if bytes:
			print("Image was sent to client successfully")
			f = open("download2%s"%url[url.rfind('.'):len(url)], 'wb')
			f.write(bytes)
			f.close()
		else:
			print("Image was not sent")
	finally:
		print('closing socket')
		sock.close()

######################################################################

#Create keys for cryptography
(public, private) = new_keys(key_size)
# Process input arguments
process_txt_files(sys.argv)
# Check if we can get metrics from server
(ping_direct,ping_number) = check_ping()
# Store all IP needed for threading into a list
tmp_list = store_ip_threading(ping_direct)
# Store IP to define every thread
(threads,tcp_threads,url_threads)=create_threads(tmp_list,ping_direct,ping_number)
# Start Threads
start_threads(threads,tcp_threads,url_threads)
# Empty lists no longer needed
empty_lists()

print("\nENDING RESULTS\n")
print("*****************************************\n")
print('The IP of relays are',relay_ip)
print('The ID of relays are',relay_id)
print('The ports of relays are',relay_ports)
print('The shortcuts of end-servers are',end_shortcut)
print('The full links of end-servers are',end_id)
print('The RTT of client to end-server is',rtt_direct_mode_list)
print('The RTT of client to every relay mode is',rtt_relay_mode_list)
print('The RTT of every ON relay to end-server is',rtt_relay_to_end)
print('The sum of RTT of the two lists above is',rtt_relay_overview)
print('The number of HOPs of client to end-server is',hops_direct_mode_list)
print('The number of HOPs of client to every relay mode is',hops_relay_mode_list)
print('The number of HOPs of every ON relay to end-server is',hops_relay_to_end)
print('The sum of HOPs of the two lists above is',hops_relay_overview)
print("\n*****************************************")

# Clean Metrics
clean_everything()
######################################################################

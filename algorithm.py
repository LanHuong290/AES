import sys
import subprocess

def install(*packages):
	for package in packages:
		# subprocess.call(['pip', 'install', package])
		reqs = subprocess.check_call([sys.executable, "-m", "pip", "install", package])
	    # installed_packages = [r.decode().split('==')[0] for r in reqs.split()]
	    # print(installed_packages)

try:
	from Crypto.Cipher import AES
	from Crypto.Random import get_random_bytes
	from Crypto.Util.Padding import pad, unpad
	from base64 import base64encode, base64decode
except:
	import pip
	install("pycryptodome",)



def aes_encrypt_ECB(data, key):
	## padding
	data = pad(data, AES.block_size)
	key = pad(data, AES.block_size)
	## encrypt
	cipher = AES.new(key, AES.MODE_ECB)
	cipherText = cipher.encrypt(data, key)
	cipherText = base64encode(cipherText).decode("utf-8")
	# return "cipherText: {}".format(cipherText)
	return {"cipherText": cipherText}

def aes_decrypt_ECB(data, key):
	## decode
	data = base64decode(data)
	## decrypt
	cipher = AES.new(key, AES.MODE_ECB)
	plainText = ciper.decrypt(data, key)
	## unpadding
	plainText.unpad(plainText, AES.block_size)
	# return "plainText: {}".format(plainText)
	return {"plainText": plainText}

def aes_encrypt_CBC(data, key, iv = None):
	## padding
	data = pad(data, AES.block_size)
	key = pad(data, AES.block_size)
	## encrypt
	cipher = AES.new(key, AES.MODE_CBC, iv = iv)
	cipherText = cipher.encrypt(data, key, iv)
	## encode
	cipherText = base64encode(cipherText).decode("utf-8")
	iv = base64encode(cipher.iv).decode("utf-8")
	# return "cipherText: {}\niv: {}".format(cipherText, iv)
	return {"cipherText": cipherText, "iv": iv}

def aes_decrypt_CBC(data, key, iv):
	## decode
	data = base64decode(data)
	iv = base64decode(iv)
	## decrypt
	cipher = AES.new(key, AES.MODE_CBC, iv = iv)
	plainText = ciper.decrypt(data, key, iv = iv)
	## unpadding
	plainText.unpad(plainText, AES.block_size)
	# return "plainText: {}".format(plainText)
	return {"plainText": plainText}
















# import sys
# import subprocess
# import copy
# import time

# import pip

# try:
# 	import Crypto.Cipher
# except:
# 	import pip
# 	install("pycryptodome")
# 	import Crypto.Cipher ## again

# def install(package):
#     subprocess.check_call([sys.executable, "-m", "pip", "install", package])
#     # subprocess.call(['pip', 'install', package])
#     ## process output with an API in the subprocess module:
# 	# reqs = subprocess.check_output([sys.executable, '-m', 'pip','sfreeze'])
# 	# installed_packages = [r.decode().split('==')[0] for r in reqs.split()]
# 	print(installed_packages)

# ## pip/pip3 -> cryptodome/pyCrypto

# ## read - write tring to tkinter obj
# ## read - write in binary file
# ## aes cipher
# ## mode cipher

# # from Crypto.Cipher import AES


# # AES_BLOCK_SIZE = 16	## byte

# # def aes_cbc_decrypt(data, key, enc_iv):
# #     """Decrypt and return `data` with AES CBC."""
# #     cipher = AES.new(key, AES.MODE_CBC, enc_iv)
# #     return cipher.decrypt(data)


# # def aes_cbc_encrypt(data, key, enc_iv):
# #     """Encrypt and return `data` with AES CBC."""
# #     cipher = AES.new(key, AES.MODE_CBC, enc_iv)
# #     return cipher.encrypt(data)


# # def stringConvert_encrypt(data, key, algo, mode, enc_iv):
# # 	cipher = algo.new(key, mode, enc_iv)
# # 	return cipher.encrypt(data)

# # def function(data, algo, key, enc_iv):



# # cipher = F.new()


# #############################################
# def readFile_input(filePath, mode = "rb"):
# 	try:
# 		with open(filePath, mode) as file:
# 			data = file.read()
# 		file.close()
# 		if not data:
# 			return None
# 	except:
# 		return False
# 	return data

# def writeFile_output(filePath, data, mode = "wb"):
# 	with open(filePath, mode) as file:
# 		file.write(data)
# 	file.close()





	


# # def readFile_ParseLine(path, numThread = 1):
# # 	def __parseLine(string):
# # 		string = string.strip()
# # 		lines = string.split("\n");
# # 		if not lines:
# # 			return None
# # 		for i in range(len(lines)):
# # 			lines[i] = lines[i].strip()
# # 			lines[i] = lines[i].split(" ")	## regex?
# # 		return lines
# # 	start = time.perf_counter()
# # 	print(f"Reading file: {path}")
# # 	try:
# # 		## type of file: "r","rb"
# # 		with open(path,"r") as file:
# # 			## multithread (?)
# # 			data = file.read()
# # 			print(f"Read file in: {time.perf_counter() - start}")
# # 		file.close()
# # 	except IOError: 
# # 		print("Error: File does not appear to exist.")
# # 		return False
# # 	else:
# # 		lines = __parseLine(data)
# # 		if not lines:
# # 			print(f"Error: File does not contain any readable data.")
# # 			return None
# # 		print(f"Success reading file.")
# # 		return lines
# # 	return None

# # def readFile_Threshold(path, numThread = 1):
# # 	print(f"Load threshold file...")
# # 	lines = readFile_ParseLine(path,numThread)
# # 	if not lines:
# # 		print(lines)	## debugging: result flag
# # 		return False
# # 	try:
# # 		thresholdList = [line[0] for line in lines]
# # 	except:
# # 		print("Error: Something was wrong with the threshold file.")
# # 		return False
# # 	else:
# # 		print("Done read threshold list.")
# # 		return thresholdList	



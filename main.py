import sys
import time
try:
	import tkinter as tk				# python 3
	from tkinter import font as tkfont  # python 3
	from tkinter import filedialog
	from Crypto.Util.Padding import pad, unpad
	from Crypto.Random import get_random_bytes
except ImportError:
	import Tkinter as tk				# python 2
	import tkFont as tkfont 			# python 2
	import tKinter.filedialog

## main function
import algorithm as alg

AES_BLOCK_SIZE = 16

class Application(tk.Tk):
	def __init__(self, *args, **kwargs):
		tk.Tk.__init__(self, *args, **kwargs)
		# self.geometry("{}x{}".format(1000,800))
		self.title("AES Cipher GUI Application")
		container = tk.Frame(self)
		container.pack(fill = "both", expand = True)
		container.grid_rowconfigure(0, weight=1)
		container.grid_columnconfigure(0, weight=1)
		## sub-frame list
		self.subFrame = {}
		self.add_frame(frame_name = "MainWindow", frame = MainWindow(parent = container, controller = self))
		self.subFrame["MainWindow"].pack(fill = "both", expand = True)
		# self.grid_frame(frame_name = "MainWindow", row = 0, column = 0, sticky = "nsew")
	def show_frame(self, frame_name):
		if frame_name not in self.subFrame:
			return None
		frame = self.subFrame[frame_name]
		try:
			frame.tkraise()
		except:
			return False
		return True
	def add_frame_detail(self, frame_name, F, parent, controller):
		self.subFrame[frame_name] = F(parent = parent, controller = controller)
	def add_frame(self, frame_name, frame, *grid):
		self.subFrame[frame_name] = frame
		if grid:
			self.subFrame[frame_name].grid(grid)
	def grid_frame(self, frame_name, row = 0, column = 0, sticky = "nsew"):
		if frame_name not in self.subFrame:
			return None
		self.subFrame[frame_name].grid(row = row, column = column, sticky = sticky)
	def pack_frame(self, frame_name, side = "top", fill = None, expand = False):
		if frame_name not in self.subFrame:
			return None
		self.subFrame[frame_name].pack(side = side, fill = fill, expand = expand)

class MainWindow(tk.Frame):
	def __init__(self, parent, controller):
		tk.Frame.__init__(self, parent)
		self.controller = controller
		container = tk.Frame(self)
		container.pack(fill = "both", expand = True)
		## frame divide
		frm_menu = tk.Frame(master = container, bg = "#333333")
		frm_menu.pack(side = "left", fill = "both")
		# frm_menu.grid(row = 0, column = 0, sticky = "ns")
		frm_utilities = tk.Frame(master = container)
		frm_utilities.pack(side = "left", fill = "both", expand = True)
		# frm_utilities.grid(row = 0, column = 1, sticky = "nsew")
		## frame menu element
		bt_string_cvt = tk.Button(master = frm_menu, text="String convert", command=lambda: controller.show_frame("StringConvert"))
		bt_file_cvt = tk.Button(master = frm_menu, text="File convert", command=lambda: controller.show_frame("FileConvert"))
		bt_home = tk.Button(master = frm_menu, text = "Home", command=lambda:controller.show_frame("Home"))
		## pack
		bt_string_cvt.pack(side = "top", fill = "x", padx = 10, pady = 10)
		bt_file_cvt.pack(side = "top", fill = "x", padx = 10, pady = 10)
		bt_home.pack(side = "bottom", fill = "x", padx = 10, pady = 10)
		## add sub-frame to be display for utilities frame
		for F in (Home, StringConvert, FileConvert):
			frame_name = F.__name__
			frame = F(parent = frm_utilities, controller = self)
			controller.subFrame[frame_name] = frame
			frame.grid(row = 0, column = 0, sticky = "nsew")
			# frame.pack()
		################
	# def zoom_out(self):
	# 	width = self.parent.winfo_width()
	# 	height = self.parent.winfo_heigh()
	# 	self.parent.geometry("{}x{}".format(min(1000,width+10), min(3000,height+20)))
	# def zoom_in(self):
	# 	width = self.parent.winfo_width()
	# 	height = self.parent.winfo_heigh()
	# 	self.parent.geometry("{}x{}".format(max(100,width-10), max(300,height-20)))

class StringConvert(tk.Frame):
	def __init__(self, parent, controller):
		# super(StringConvert, self).__init__()
		tk.Frame.__init__(self, parent)
		## variable initial
		cipher = tk.StringVar()
		cipher.set("aes128")
		mode = tk.StringVar()
		mode.set("ECB")
		strVar_key = tk.StringVar()
		strVar_key_status = tk.StringVar()
		strVar_key_status.set("Key status here.")
		strVar_mode_CBC_iv = tk.StringVar()
		strVar_mode_CBC_iv.set("")
		strVar_alert_message = tk.StringVar()
		strVar_alert_message.set("")
		## main object contain inittial
		self.controller = controller
		container = tk.Frame(self)
		container.pack(fill = "both", expand = True)
		## frame divide
		frm_field = tk.Frame(master = container)
		frm_option = tk.Frame(master = container)
		frm_field.pack(side = "top", fill = "both")#, expand = True)
		frm_option.pack(side = "bottom", fill = "both")
		##
		frm_input = tk.Frame(master = frm_field)
		frm_output = tk.Frame(master = frm_field)
		frm_key = tk.Frame(master = frm_field)
		frm_cipher = tk.Frame(master = frm_option, bg = "grey")
		frm_mode = tk.Frame(master = frm_option, bg = "grey")
		frm_button = tk.Frame(master = frm_option, bg = "grey")
		frm_key.pack(side = "bottom", fill = "both", expand = True)
		frm_input.pack(side = "left", fill = "both", expand = True)
		frm_output.pack(side = "left", fill = "both", expand = True)
		frm_cipher.pack(side = "top", fill = "both", expand = True)
		frm_mode.pack(side = "top", fill = "both", expand = True)
		frm_button.pack(side = "top", fill = "both", expand = True)
		## sub-frame field element
		lb_input = tk.Label(master = frm_input, text = "Input")
		text_input = tk.Text(master = frm_input, width = 50, height = 20)
		lb_output = tk.Label(master = frm_output, text = "Output")
		text_output = tk.Text(master = frm_output, width = 50, height = 20)
		lb_key = tk.Label(master = frm_key, text = "Key")
		bt_key_browse = tk.Button(master = frm_key, text = "Browse", command = lambda: browse_file(strVar_key))
		lb_key_status = tk.Label(master = frm_key, textvariable = strVar_key_status)
		bt_key_replace = tk.Button(master = frm_key, text = "Copy and replace", command = lambda: self.replace_text(strVar_key, strVar_key_status))
		entry_key = tk.Entry(master = frm_key, textvariable = strVar_key, width = 50, justify = "left")
		# strVar_key.trace("w", lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		## sub-frame option element
		lb_cipher = tk.Label(master = frm_cipher, text = "Cipher")
		rbt_cipher_aes128 = tk.Radiobutton(master = frm_cipher, text = "AES128", variable=cipher, value = "aes128", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		rbt_cipher_aes192 = tk.Radiobutton(master = frm_cipher, text = "AES192", variable=cipher, value = "aes192", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		rbt_cipher_aes256 = tk.Radiobutton(master = frm_cipher, text = "AES256", variable=cipher, value = "aes256", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		lb_mode = tk.Label(master = frm_mode, text = "Mode")
		rbt_mode_ECB = tk.Radiobutton(master = frm_mode, text = "ECB", variable=mode, value = "ECB", command = lambda: self.choose_mode(mode, {"lb_mode_CBC_iv" : lb_mode_CBC_iv, "entry_mode_CBC_iv" : entry_mode_CBC_iv, "strVar_mode_CBC_iv" : strVar_mode_CBC_iv}))
		rbt_mode_CBC = tk.Radiobutton(master = frm_mode, text = "CBC", variable=mode, value = "CBC", command = lambda: self.choose_mode(mode, {"lb_mode_CBC_iv" : lb_mode_CBC_iv, "entry_mode_CBC_iv" : entry_mode_CBC_iv, "strVar_mode_CBC_iv" : strVar_mode_CBC_iv}))
		lb_mode_CBC_iv = tk.Label(master = frm_mode, text = "Initial Vector for CBC mode")
		entry_mode_CBC_iv = tk.Entry(master = frm_mode, textvariable = strVar_mode_CBC_iv, justify = "left")
		##
		bt_encrypt = tk.Button(master = frm_button, text = "Encrypt", command = lambda: self.encrypt(text_input, strVar_key_status, text_output, strVar_alert_message, cipher, mode))	## command = 
		bt_decrypt = tk.Button(master = frm_button, text = "Decrypt", command = lambda: self.decrypt(text_input, strVar_key_status, text_output, strVar_alert_message, cipher, mode))
		bt_swap = tk.Button(master = frm_button, text = "Swap")
		lb_alert_message = tk.Label(master = frm_button, textvariable = strVar_alert_message)
		# ## sub-frame field element grid
		lb_input.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)		## frm_input
		text_input.grid(row = 1, column = 0, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_output.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)	## frm_output
		text_output.grid(row = 1, column = 0, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_key.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)		## frm_key
		entry_key.grid(row = 0, column = 1, sticky = "ew", padx = 5, pady = 5)
		bt_key_browse.grid(row = 0, column = 2, sticky = "w", padx = 5, pady = 5)
		bt_key_replace.grid(row = 0, column = 3, sticky = "w", padx = 5, pady = 5)
		lb_key_status.grid(row = 1, column = 1, sticky = "w", padx = 5, pady = 5)
		## sub-frame option element grid
		lb_cipher.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes128.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes192.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes256.grid(row = 0, column = 3, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_mode.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		rbt_mode_ECB.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		rbt_mode_CBC.grid(row = 1, column = 1, sticky = "nsew", padx = 5, pady = 5)
		lb_mode_CBC_iv.grid(row = 1, column = 2, sticky = "nsew", padx = 5, pady = 5)
		entry_mode_CBC_iv.grid(row = 1, column = 3, sticky = "nsew", padx = 5, pady = 5)
		##
		bt_encrypt.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		bt_decrypt.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		bt_swap.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		# lb_alert_message.grid(row = 1, column = 0, sticky = "nsew", padx = 10, pady = 10)
		## other		
	def enable_alert(lb_alert_message):
		## if strVar_alert_message not empty
		lb_alert_message.config(state = "enable")
	def disable_alert_message(lb_alert_message):
		## if strVar_alert_message if empty
		lb_alert_message.config(state = "enable")
	def encrypt(self, text_input, strVar_key_status, text_output, cipher = "AES128", mode = "ECB", args = {}):
		data = text_input.get("1.0","end")
		key = strVar_key_status.get().encode()
		try:
			if cipher == "AES128" or cipher == "AES192" or cipher == "AES256":
				if mode == "EBC":
					result = alg.aes_encrypt_EBC(data, key)
					self.text_update(text_output, result["cipherText"])
				elif mode == "CBC":
					result = alg.aes_encrypt_CBC(data, key)
					self.text_update(text_output, result["cipherText"])
					args["strVar_mode_CBC_iv"].set(result["iv"])
		except:
			result = "There is some thing wrong here, please try again."
			self.text_update(text_output, result)
	def decrypt(self, text_input, strVar_key_status, text_output, cipher = "AES128", mode = "ECB", args = {}):
		data = text_input.get("1.0","end")
		key = strVar_key_status.get().encode()
		try:
			if cipher == "AES128" or cipher == "AES192" or cipher == "AES256":
				if mode == "EBC":
					result = alg.aes_decrypt_EBC(data, key)
					self.text_update(text_output, result["plainText"])
				elif mode == "CBC":
					result = alg.aes_decrypt_CBC(data, key, args["strVar_mode_CBC_iv"])
					self.text_update(text_output, result["plainText"])
		except:
			result = "There is some thing wrong here, please try again."
			self.text_update(text_output, result)
	def enable_state(self, obj):
		obj.config(state = "normal")
	def enable_grid(self, obj, row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5):
		obj.grid( row = row, column = column, sticky = sticky, padx = padx, pady = pady)
	def disable_grid(self, obj):
		grid_info = obj.grid_info()
		obj.grid_forget()
		return grid_info
	def replace_text(self,strVar_text1, strVar_text2):
		strVar_text1.set(strVar_text2.get())
	def choose_cipher(self, strVar_key,	strVar_key_status, cipher = "aes128", *args):
		key = strVar_key.get().encode()
		if cipher.get() == "aes128":
			if len(key) == 0:
				key = get_random_bytes(16)
			else:
				key = pad(key[:16],16).decode("utf-8")				
		elif cipher.get() == "aes192":
			if len(key) == 0:
				key = get_random_bytes(32)
			else:
				key = pad(key[:32],32).decode("utf-8")	
		elif cipher.get() == "aes256":
			if len(key) == 0:
				key = get_random_bytes(64)
			else:
				key = pad(key[:64],64).decode("utf-8")
		strVar_key_status.set(key)	
	def choose_mode(self, mode = "ECB", objList = {}):
		if mode == "ECB":
			objList["strVar_mode_CBC_iv"].set("")
			self.disable_grid(objList["lb_mode_CBC_iv"])
			self.disable_grid(objList["entry_mode_CBC_iv"])
		elif mode == "CBC":
			self.enable_grid(objList["lb_mode_CBC_iv"],row = 1, column = 2, sticky = "nsew", padx = 10, pady = 10)
			self.enable_grid(objList["entry_mode_CBC_iv"],row = 1, column = 3, sticky = "nsew", padx = 10, pady = 10)
	def text_clear(self, text):
		text.delete("1.0","end")
	def text_insert(self, text, value):
		text.insert("end", value)
	def text_update(self, text, value = ""):
		self.text_clear(text)
		self.text_insert(text, value)
	def test(self):
		print(value)
	
# self.choose_cipher(strVar_key, lb_key_status, cipher)




class FileConvert(tk.Frame):
	def __init__(self, parent, controller):
		# super(FileConvert, self).__init__()
		tk.Frame.__init__(self, parent)
		## variable initial
		cipher = tk.StringVar()
		cipher.set("aes128")
		mode = tk.StringVar()
		mode.set("ECB")
		strVar_input = tk.StringVar()
		strVar_key = tk.StringVar()
		strVar_key_status = tk.StringVar()
		strVar_key_status.set("Key status here.")
		strVar_mode_CBC_iv = tk.StringVar()
		strVar_mode_CBC_iv.set("")
		strVar_alert_message = tk.StringVar()
		strVar_alert_message.set("")
		self.controller = controller
		container = tk.Frame(self)
		container.pack(fill = "both", expand = True)
		## frame divide
		frm_field = tk.Frame(master = container)
		frm_option = tk.Frame(master = container)
		frm_field.pack(side = "top", fill = "both", expand = True)
		frm_option.pack(side = "bottom", fill = "x", expand = True)
		## sub-frame init
		frm_input = tk.Frame(master = frm_field)
		frm_output = tk.Frame(master = frm_field)
		frm_key = tk.Frame(master = frm_field)
		frm_cipher = tk.Frame(master = frm_option, bg = "grey")
		frm_mode = tk.Frame(master = frm_option, bg = "grey")
		frm_button = tk.Frame(master = frm_option, bg = "grey")
		## pack
		frm_input.pack(side = "top", fill = "both", expand = True)
		frm_key.pack(side = "top", fill = "both", expand = True)
		frm_output.pack(side = "top", fill = "both", expand = True)
		frm_cipher.pack(side = "top", fill = "both", expand = True)
		frm_mode.pack(side = "top", fill = "both", expand = True)
		frm_button.pack(side = "top", fill = "both", expand = True)
		## sub-frame field element
		lb_input = tk.Label(master = frm_input, text = "Input")
		entry_input = tk.Entry(master = frm_input, textvariable = strVar_input, width = 60, justify = "left")
		bt_input_browse = tk.Button(master = frm_input, text = "Browse", command = lambda: browse_file(strVar_input))
		lb_input_messsage = tk.Label(master = frm_input, text = "Nothing wrong here.")
		##
		lb_key = tk.Label(master = frm_key, text = "Key")
		entry_key = tk.Entry(master = frm_key, textvariable = strVar_key, width = 60, justify = "left")
		bt_key_browse = tk.Button(master = frm_key, text = "Browse", command = lambda: browse_file(strVar_key))
		lb_key_status = tk.Label(master = frm_key, textvariable = strVar_key_status)
		##
		lb_output = tk.Label(master = frm_output, text = "Output")
		text_output = tk.Text(master = frm_output)
		lb_output_save = tk.Label(master = frm_output, text = "Save to")
		strVar_save = tk.StringVar()
		entry_output_save = tk.Entry(master = frm_output, textvariable = "Choose save file path", justify = "left")
		bt_output_browse = tk.Button(master = frm_output, text = "Browse", command = lambda: browse_file(strVar_save))
		bt_output_save = tk.Button(master = frm_output, text = "Save")
		lb_output_message = tk.Label(master = frm_output, text = "Nothing wrong here too.")
		## sub-frame field element grid
		lb_input.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)
		entry_input.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		bt_input_browse.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		lb_input_messsage.grid(row = 1, column = 1, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_key.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)
		entry_key.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		bt_key_browse.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		lb_key_status.grid(row = 1, column = 1, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_output.grid(row = 0, column = 0, sticky = "w", padx = 5, pady = 5)
		text_output.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		lb_output_message.grid(row = 1, column = 1, sticky = "nsew", padx = 5, pady = 5)
		lb_output_save.grid(row = 2, column = 0, sticky = "w", padx = 5, pady = 5)
		entry_output_save.grid(row = 2, column = 1, sticky = "nsew", padx = 5, pady = 5)
		bt_output_browse.grid(row = 2, column = 2, sticky = "nsew", padx = 5, pady = 5)
		bt_output_save.grid(row = 2, column = 3, sticky = "nsew", padx =5, pady = 5)
		## sub-frame option element
		lb_cipher = tk.Label(master = frm_cipher, text = "Cipher")
		rbt_cipher_aes128 = tk.Radiobutton(master = frm_cipher, text = "AES128", variable=cipher, value = "aes128", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		rbt_cipher_aes192 = tk.Radiobutton(master = frm_cipher, text = "AES192", variable=cipher, value = "aes192", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		rbt_cipher_aes256 = tk.Radiobutton(master = frm_cipher, text = "AES256", variable=cipher, value = "aes256", command = lambda: self.choose_cipher(strVar_key, strVar_key_status, cipher))
		lb_mode = tk.Label(master = frm_mode, text = "Mode")
		rbt_mode_ECB = tk.Radiobutton(master = frm_mode, text = "ECB", variable=mode, value = "ECB", command = lambda: self.choose_mode(mode, {"lb_mode_CBC_iv" : lb_mode_CBC_iv, "entry_mode_CBC_iv" : entry_mode_CBC_iv, "strVar_mode_CBC_iv" : strVar_mode_CBC_iv}))
		rbt_mode_CBC = tk.Radiobutton(master = frm_mode, text = "CBC", variable=mode, value = "CBC", command = lambda: self.choose_mode(mode, {"lb_mode_CBC_iv" : lb_mode_CBC_iv, "entry_mode_CBC_iv" : entry_mode_CBC_iv, "strVar_mode_CBC_iv" : strVar_mode_CBC_iv}))
		lb_mode_CBC_iv = tk.Label(master = frm_mode, text = "Initial Vector for CBC mode")
		entry_mode_CBC_iv = tk.Entry(master = frm_mode, textvariable = strVar_mode_CBC_iv, justify = "left")
		##
		bt_encrypt = tk.Button(master = frm_button, text = "Encrypt") #, command = lambda: self.encrypt(text_input, strVar_key_status, text_output, strVar_alert_message, cipher, mode))	## command = 
		bt_decrypt = tk.Button(master = frm_button, text = "Decrypt") #, command = lambda: self.decrypt(text_input, strVar_key_status, text_output, strVar_alert_message, cipher, mode))
		bt_swap = tk.Button(master = frm_button, text = "Swap")
		lb_alert_message = tk.Label(master = frm_button, textvariable = strVar_alert_message)
		## sub-frame option element grid
		lb_cipher.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes128.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes192.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		rbt_cipher_aes256.grid(row = 0, column = 3, sticky = "nsew", padx = 5, pady = 5)
		##
		lb_mode.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		rbt_mode_ECB.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		rbt_mode_CBC.grid(row = 1, column = 1, sticky = "nsew", padx = 5, pady = 5)
		lb_mode_CBC_iv.grid(row = 1, column = 2, sticky = "nsew", padx = 5, pady = 5)
		entry_mode_CBC_iv.grid(row = 1, column = 3, sticky = "nsew", padx = 5, pady = 5)
		##
		bt_encrypt.grid(row = 0, column = 0, sticky = "nsew", padx = 5, pady = 5)
		bt_decrypt.grid(row = 0, column = 1, sticky = "nsew", padx = 5, pady = 5)
		bt_swap.grid(row = 0, column = 2, sticky = "nsew", padx = 5, pady = 5)
		# lb_cipher = tk.Label(master = frm_option, text = "Cipher")
		# rbt_cipher_aes128 = tk.Radiobutton(master = frm_option, text = "AES128", variable=cipher, value = 0)
		# rbt_cipher_aes256 = tk.Radiobutton(master = frm_option, text = "AES256", variable=cipher, value = 1)
		# lb_mode = tk.Label(master = frm_option, text = "Mode")
		# rbt_mode_CBC = tk.Radiobutton(master = frm_option, text = "CBC", variable=mode, value = 2)
		# rbt_mode_ECB = tk.Radiobutton(master = frm_option, text = "ECB", variable=mode, value = 3)
		# bt_encrypt = tk.Button(master = frm_option, text = "Encrypt")	## command = 
		# bt_decrypt = tk.Button(master = frm_option, text = "Decrypt")
		# bt_swap = tk.Button(master = frm_option, text = "Swap")
		# lb_alert_message = tk.Label(master  =frm_option, text = "Alert message here.")	## state = DISABLE
		# ## frame option element grid
		# lb_cipher.grid(row = 0, column = 0, sticky = "nsew", padx = 10, pady = 10)
		# rbt_cipher_aes128.grid(row = 0, column = 1, sticky = "nsew", padx = 10, pady = 10)
		# rbt_cipher_aes256.grid(row = 0, column = 2, sticky = "nsew", padx = 10, pady = 10)
		# lb_mode.grid(row = 1, column = 0, sticky = "nsew", padx = 10, pady = 10)
		# rbt_mode_CBC.grid(row = 1, column = 1, sticky = "nsew", padx = 10, pady = 10)
		# rbt_mode_ECB.grid(row = 1, column = 2, sticky = "nsew", padx = 10, pady = 10)
		# bt_encrypt.grid(row = 0, column = 3, sticky = "nsew", padx = 10, pady = 10)
		# bt_decrypt.grid(row = 0, column = 4, sticky = "nsew", padx = 10, pady = 10)
		# bt_swap.grid(row = 0, column =5, sticky = "nsew", padx = 5, pady = 10)
		# lb_alert_message.grid(row = 0, column = 6, sticky = "nsew", padx = 10, pady = 10)
	def choose_cipher(self, strVar_key,	strVar_key_status, cipher = "aes128", *args):
		key = strVar_key.get().encode()
		if cipher.get() == "aes128":
			if len(key) == 0:
				key = get_random_bytes(16)
			else:
				key = pad(key[:16],16).decode("utf-8")				
		elif cipher.get() == "aes192":
			if len(key) == 0:
				key = get_random_bytes(32)
			else:
				key = pad(key[:32],32).decode("utf-8")	
		elif cipher.get() == "aes256":
			if len(key) == 0:
				key = get_random_bytes(64)
			else:
				key = pad(key[:64],64).decode("utf-8")
		strVar_key_status.set(key)	
	def choose_mode(self, mode = "ECB", objList = {}):
		if mode == "ECB":
			objList["strVar_mode_CBC_iv"].set("")
			self.disable_grid(objList["lb_mode_CBC_iv"])
			self.disable_grid(objList["entry_mode_CBC_iv"])
		elif mode == "CBC":
			self.enable_grid(objList["lb_mode_CBC_iv"],row = 1, column = 2, sticky = "nsew", padx = 10, pady = 10)
			self.enable_grid(objList["entry_mode_CBC_iv"],row = 1, column = 3, sticky = "nsew", padx = 10, pady = 10)	

class Home(tk.Frame):
	def __init__(self, parent, controller):
		# super(Home, self).__init__()
		tk.Frame.__init__(self, parent)
		self.controller = controller
		container = tk.Frame(self)
		container.pack( side = "top", fill = "both", expand = True)
		frm_descripton = tk.Frame(master = container)
		frm_members = tk.Frame(master = container)
		frm_descripton.pack(side = "top", expand = True)
		frm_members.pack(side = "top", expand  =True)
		# frm_descripton.grid(row = 0, column = 0, sticky = "nsew")
		# frm_members.grid(row = 1, column = 0, sticky = "nsew")
		##
		lb_desciption = tk.Label(master = frm_descripton, text = "descripton")
		lb_desciption.grid(row = 0, column = 0, sticky = "nsew")
		##
		lb_member = tk.Label(master = frm_members, text = "Members")
		lb_member1= tk.Label(master = frm_members, text = "A")
		lb_member2= tk.Label(master = frm_members, text = "B")
		lb_member3= tk.Label(master = frm_members, text = "C")
		lb_member4= tk.Label(master = frm_members, text = "D")
		lb_member.pack(side = "top", fill = "x")
		lb_member1.pack(side = "top", fill = "x")
		lb_member2.pack(side = "top", fill = "x")
		lb_member3.pack(side = "top", fill = "x")
		lb_member4.pack(side = "top", fill = "x")
		## grid
		# lb_member.grid(row = 0, column = 0, sticky = "nsew")
		# lb_member1.grid(row = 1, column = 0, sticky = "nsew")
		# lb_member2.grid(row = 2, column = 0, sticky = "nsew")
		# lb_member3.grid(row = 3, column = 0, sticky = "nsew")
		# lb_member4.grid(row = 4, column = 0, sticky = "nsew")

## browse button
def browse_file(filename):	## stingVar type
	filename.set(tk.filedialog.askopenfilename(initialdir = "./", title = "Select a File", filetypes = (("all files","*.*"),("Text files","*.txt*"),)))
	return filename



def main():
	app = Application()
	app.show_frame("MainWindow")
	# app.show_frame("Home")
	app.show_frame("StringConvert")
	# app.show_frame("FileConvert")
	app.mainloop()

if __name__ == "__main__":
	main()





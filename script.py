#!/usr/bin/python

# from pwn import *
import requests
import base64
import json
import sys

url = "" # SET THE HOST
service = "/encrypt?plaintext="
initial_padding = ("A"*47).encode("hex")
#flag_begin = "247CTF{"
possible_letters = ['a', 'b', 'c', 'd', 'e', 'f', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
byte_to_find = ''
flag_so_far = ''

IV = ''

request_session = requests.Session()

#### METHOD TO CHECK IV FROM ACTUAL REQUEST COOKIES####
def get_IV_from_cookies(cookies_dict):
	cookie_json = json.dumps(cookies_dict)
	cookie_json = json.loads(cookie_json)
	print "WHAt????????????????'''" + str(cookie_json)
	cookie_json = cookie_json['session']
	#print "[+] COOKIES:" + cookie_json
	cookie_json = cookie_json.split(".")[0]
	padding = len(cookie_json) % 4
	cookie_json = cookie_json + "="*padding
	cookie_json = base64.b64decode(cookie_json)
	#print "[+] COOKIES: b64: " + cookie_json
	cookie_json = json.loads(cookie_json)
	cookie_json = cookie_json['IV']
	cookie_json = json.dumps(cookie_json)
	cookie_json = json.loads(cookie_json)
	cookie_json = cookie_json[' b']
	#print "[+] COOKIES: b64: " + cookie_json
	aux_IV = base64.b64decode(cookie_json).encode("hex")
	#print "[+] COOKIES: b64: INITIALIZATION_VECTOR=== > " + aux_IV
	return aux_IV

def modify_global_iv(string):
	global IV
	IV = string
	print "[+] IV GLOBAL SET TO: " + IV.encode("hex")

# Return hex already
def xor_two_str(a,b):
    xored = []
    print "XORING " + a.encode("hex") + "\nWITH   " + b.encode("hex") + "\n"
    for i in range(len(a)):
        xored_value = ord(a[i%len(a)]) ^ ord(b[i%len(b)])
        hex_value = hex(xored_value)[2:]
        if len(hex_value) == 1:
        	hex_value = "0" + hex_value
        xored.append(hex_value)

    print "RESULT OF XOR: " + ''.join(xored)
    return ''.join(xored)

def get_initial_IV(padding):
	result = request_session.request('GET', url)
	IV_from_cookies = get_IV_from_cookies(result.cookies.get_dict())
	print "[+] IV FROM COOKIES:" + IV_from_cookies
	#result = str(wget(url+service+padding))
	#print "[+] RESULT:" + result.text
	modify_global_iv(IV_from_cookies.decode("hex"))

def request_cipher_text_and_get_IV(padding):
	print "Sending padding:" + padding + " length: " + str(len(padding))
	padding = xor_two_str(IV, padding[:32].decode("hex")) + padding[32:]
	result = request_session.request('GET', url+service+padding)
	print "Result: " + result.text
	print "[+] Result to look after:" + result.text[64:96] # 0-31 (first 16 bytes) . 32 - 63 (second 16 bytes) . 64 - 97 (third 16 bytes)
	global byte_to_find
	byte_to_find = result.text[64:96]# Insted of comparing last byte, all 32 bytes must be compared
	modify_global_iv(result.text[-32:].decode("hex"))



get_initial_IV(initial_padding)
request_cipher_text_and_get_IV(initial_padding)

local_padding = initial_padding
while True:
	
	for letter in possible_letters:

		print "####### \n\nSending request with IV:" + IV.encode("hex")
		print "Trying letter:" + letter
		xored_local_padding = xor_two_str(IV, local_padding[:32].decode("hex"))

		local_padding_to_send =  xored_local_padding + local_padding[32:]
		print "++++++++++++++++++++++++++++++++++++++++++ length: " + str(len(local_padding_to_send))
		print "[+] SENDING REQUEST TO:" + url+service+local_padding_to_send + flag_so_far.encode("hex") + letter.encode("hex")
		local_result = request_session.request('GET', url+service+local_padding_to_send + flag_so_far.encode("hex") + letter.encode("hex"))
		print "[+]RESULT:" + local_result.text
		modify_global_iv(local_result.text[-32:].decode("hex"))
		print "############################### RESULT WE LOOK AFTER: " + byte_to_find
		print "############################### RESULT WE       HAVE: " + local_result.text[64:96]

		if local_result.text[64:96] == byte_to_find:
			print "BYTE FOUND! for the letter:" + letter 
			global flag_so_far
			flag_so_far = flag_so_far + letter
			print "[!][!][!][!][!][!] Flag so far:" + flag_so_far
			local_padding = local_padding[0:len(local_padding)-2]
			request_cipher_text_and_get_IV(local_padding)
			break
		
	if len(flag_so_far) == 32:
		break

print "Flag:" + flag_so_far + "}"
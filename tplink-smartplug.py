#!/usr/bin/env python
# 
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#  
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 
#
import socket
import argparse
import json
import sys

version = 0.1

# Check if IP is valid
def validIP(ip):
	try:
		socket.inet_pton(socket.AF_INET, ip)
	except socket.error:
		parser.error("Invalid IP Address.")
	return ip 

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink-smarthome-commands.txt
# Also at https://github.com/softScheck/tplink-smartplug/blob/master/tplink-smarthome-commands.txt
commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
			'on'       : '{"system":{"set_relay_state":{"state":1}}}',
			'off'      : '{"system":{"set_relay_state":{"state":0}}}',
			'cloudinfo': '{"cnCloud":{"get_info":{}}}',
			'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
			'time'     : '{"time":{"get_time":{}}}',
			'schedule' : '{"schedule":{"get_rules":{}}}',
			'countdown': '{"count_down":{"get_rules":{}}}',
			'antitheft': '{"anti_theft":{"get_rules":{}}}',
			'reboot'   : '{"system":{"reboot":{"delay":1}}}',
			'reset'    : '{"system":{"reset":{"delay":1}}}',
			'emeter'   : '{"emeter":{"get_realtime":{}}}',
			'current'  : '{"emeter":{"get_realtime":{}}}',
			'voltage'  : '{"emeter":{"get_realtime":{}}}',
			'power'    : '{"emeter":{"get_realtime":{}}}',
			'total'    : '{"emeter":{"get_realtime":{}}}',
			'gains'    : '{"emeter":{"get_vgain_igain":{}}}',
}

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = "\0\0\0\0"
	for i in string: 
		a = key ^ ord(i)
		key = a
		result += chr(a)
	return result

def decrypt(string):
	key = 171 
	result = ""
	for i in string: 
		a = key ^ ord(i)
		key = ord(i) 
		result += chr(a)
	return result

# Parse commandline arguments
parser = argparse.ArgumentParser(description="TP-Link Wi-Fi Smart Plug Client v" + str(version))
parser.add_argument("-t", "--target", metavar="<ip>", required=True, help="Target IP Address", type=validIP)
parser.add_argument("-o", "--timeout", metavar="<seconds>", required=False, help="Timeout for connecting to target (default is 5)", type=int, default=5)
parser.add_argument("-e", "--echo", help="Echo sent command as well", action='store_true')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands) 
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")
# group.add_argument("-l", "--list", metavar="", help="Display the list of available JSON commands (contents of tplink-smarthome-commands.txt)")
args = parser.parse_args()

# Set target IP, port and command to send
ip = args.target
port = 9999
if args.command is None:
	cmd = args.json
else:
	cmd = commands[args.command]



# Send command and receive reply 
try:
	sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_tcp.settimeout(args.timeout)
	sock_tcp.connect((ip, port))
	if args.echo:
		# sys.stderr.write("%s\n" % cmd)
		print cmd
	sock_tcp.send(encrypt(cmd))
	data = sock_tcp.recv(2048)
	sock_tcp.close()
	response = decrypt(data[4:])
	if args.command and any(c in args.command for c in ['voltage', 'current', 'power', 'total']):
		obj = json.loads(response)
		print obj['emeter']['get_realtime'][args.command]
	else:
		print response  # make parsable (to things like jq)
except socket.error, e:
	sys.stderr.write("Error: Cound not connect to %s:%d (%s)\n" % (ip, port, e))
	raise SystemExit(10 if e == 'timed out' else 3)

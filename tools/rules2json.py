#!/usr/bin/python

# This file converts standard rules in audit.rules to json rules

from collections import OrderedDict
import json
import sys
import re

if len(sys.argv) <=  1:
	print("No rule file specified")
	exit()

with open(sys.argv[1], 'r') as my_file:
	rules = my_file.readlines()
	watches = []
	syscalls = []
	final = OrderedDict()
	for rule in rules:
		#ignore if don't start with '-'
		if rule[0] == "-":
			rule = rule.split()
			if rule[0] == "-w":
				# parse watches on file system
				watch_json = {'path':rule[1]}

				if len(rule) >= 2:
					if rule[2] == "-p":
						if len(rule) > 4 and rule[4] == "-k":
							watch_json['permission'] = rule[3]
							watch_json['key'] = rule[5] 
						else:
							watch_json['permission'] = rule[3]
					elif rule[2] == "-k": 
						if len(rule) > 4 and rule[4] == "-p":
							watch_json['permission'] = rule[5]
							watch_json['key'] = rule[3] 
						else:
							watch_json['key'] = rule[3]
				else:
					print("Invalid rule: "+" ".join(rule))
					exit()
				watches.append(watch_json)
			elif rule[0] == "-a" or rule[0] == "-A":
				#TODO: Add support for -A
				# parse syscalls
				actions = rule[1].split(",")
				syscall_json = {'actions':actions, "fields":[], "syscalls":[]}
				for i in range(2, len(rule)):
					if rule[i] == "-S":
						syscall_json["syscalls"].append(rule[i+1])
					elif rule[i] == "-F":
						result = re.match("(.+)(!=|>=|<=|&=|=|>|<|&)(.+)", rule[i+1])
						if result:
							op = result.group(2)
							if op == "!=":
								opval =  "nt_eq"
							elif op == ">=":
								opval = "gt_or_eq"
							elif op == "<=":
								opval = "lt_or_eq"
							elif op == "&=":
								opval = "and_eq"
							elif op == "=":
								opval = "eq"
							elif op == ">":
								opval = "gt"
							elif op == "<":
								opval = "lt"
							elif op == "&":
								opval = "and"

							fieldname = result.group(1)
							fieldval = result.group(3)
							if fieldname == "arch":
								fieldval = int(fieldval[1:])
							try:
								if fieldval.isdigit():
									fieldval = int(fieldval)
							except:
								pass
							syscall_json["fields"].append({"name":fieldname, "op": opval, "value":fieldval})
					elif rule[i] == "-k":
						syscall_json["key"] = rule[i+1]

				if not syscall_json["syscalls"]:
					del syscall_json["syscalls"]
				if not syscall_json["fields"]:
					del syscall_json["fields"]
				syscalls.append(syscall_json)
			elif rule[0] == "-D":
				final["delete"] = True
			elif rule[0] == "-b":
				final["buffer"] = rule[1]
			elif rule[0] == "-e":
				final["enable"] = rule[1]
			elif rule[0] == "-r":
				final["rate"] = rule[1]
	final["file_rules"] = watches
	final["syscall_rules"] = syscalls
	final = json.dumps(final, indent=4, separators=(',', ': '))
	print(final)

#with open('audit.rules.json', 'w') as outfile:
	#outfile.write(final)
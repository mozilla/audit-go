#!/usr/bin/python

# This file converts standard rules in audit.rules to json rules 

import sys
import re

with open(sys.argv[1], 'r') as my_file:
	rules = my_file.readlines()
	watches = []
	syscalls = []
	final = {}
	for rule in rules:
		#ignore if don't start with '-'
		if rule[0] == "-":
			rule = rule.split()
			if rule[0] == "-w":
				# parse watches on file system
				json = {'path':rule[1]}

				if len(rule) >= 2:
					if rule[2] == "-p":
						if len(rule) > 4 and rule[4] == "-k":
							json['permission'] = rule[3]
							json['key'] = rule[5] 
						else:
							json['permission'] = rule[3]
					elif rule[2] == "-k": 
						if len(rule) > 4 and rule[4] == "-p":
							json['permission'] = rule[5]
							json['key'] = rule[3] 
						else:
							json['key'] = rule[3]
				else:
					print("Invalid rule: "+" ".join(rule))
					exit()
				watches.append(json)
			elif rule[0] == "-a":
				#TODO: Add support for -A
				# parse syscalls
				actions = rule[1].split(",")
				json = {'actions':actions, "fields":[], "syscalls":[]}
				for i in range(2, len(rule)):
					if rule[i] == "-S":
						json["syscalls"].append(rule[i+1])
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

							json["fields"].append({"name":fieldname, "op": opval, "value":fieldval})
					elif rule[i] == "-k":
						json["key"] = rule[i+1]

				if not json["syscalls"]:
					del json["syscalls"]
				if not json["fields"]:
					del json["fields"]
				syscalls.append(json)
			elif rule[0] == "-D":
				final["delete"] = True
			elif rule[0] == "-b":
				final["buffer"] = rule[1]
			elif rule[0] == "-e":
				final["enable"] = rule[1]
			elif rule[0] == "-r":
				final["rate"] = rule[1]

	print final
	print watches
	print syscalls

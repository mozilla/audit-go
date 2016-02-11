#!/usr/bin/python

# This file converts standard rules in audit.rules to json rules 

import sys

with open(sys.argv[1], 'r') as my_file:
	rules = my_file.readlines()
	watches = []
	syscalls = []
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
				# parse syscalls
				actions = rule[1].split(",")
				json = {'actions':actions, "fields":[], "syscalls":[]}
				for i in range(2, len(rule)):
					if rule[i] == "-S":
						json["syscalls"].append(rule[i+1])
					elif rule[i] == "-F":
						# fix this
						json["fields"].append(rule[i+1])
					elif rule[i] == "-k":
						json["key"] = rule[i+1]
				if not json["syscalls"]:
					del json["syscalls"]
				if not json["fields"]:
					del json["fields"]
				syscalls.append(json)
			#else:
				#print(rule)
	print watches
	print syscalls

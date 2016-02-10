#!/usr/bin/python

# This file converts standard rules in audit.rules to json rules 

import sys

with open(sys.argv[1], 'r') as my_file:
	rules = my_file.readlines()
	watches = []
	for rule in rules:
		#ignore if don't start with '-'
		if rule[0] == "-":
			rule = rule.split()
			if rule[0] == "-w":
				# parse watches on file system
				if len(rule) > 4 and rule[2] == "-p" and rule[4] == "-k":
					perm = rule[3]
					kname = rule[5]
				elif len(rule) > 4 and rule[2] == "-k" and rule[4] == "-p":
					perm = rule[5]
					kname = rule[3]
				elif len(rule) == 4 and rule[2] == "-p":
					perm = rule[3]
				else:
					print("Invalid rule: "+" ".join(rule))
					exit()
				watches.append({'path':rule[1], 'permission': perm, 'key': kname})
			elif rule[0] == "-a":
				# parse syscalls
				print(rule)
			else:
				print(rule)
	#print watches
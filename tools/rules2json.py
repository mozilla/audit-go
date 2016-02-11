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
				# TODO: take note of -a and -A
				print(rule)
			#else:
				#print(rule)
	print watches
# -w /etc/syslog.conf
# -w /etc/syslog-ng.conf -p wa -k syslog
# -w /etc/syslog.conf -p wa 
# -w /etc/rsyslog.conf -k syslog -p wa
# -w /etc/rsyslog-ng/ -k syslog


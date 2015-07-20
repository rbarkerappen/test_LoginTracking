#!/usr/bin/env python

import random


def getRandomIP():
	"""
	TODO
	"""
	ips = [
		"99.104.33.27", 
		"73.49.80.218", 
		"99.229.118.210", 
		"220.240.23.55", 
		"41.69.185.181",
		"209.141.184.17",
		"114.108.200.43",
		"108.51.130.9",
	]

	random.shuffle(ips)

	return ips[0]

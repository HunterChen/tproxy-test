#!/usr/bin/env python
from TestAgentImpl import TestAgentImpl
import sys,os

try:
	os.system("rm -f log")
	i = TestAgentImpl(sys.stdin, sys.stdout)
	while i.dispatch_command():
		i.log("dispatch new command")
		pass
		i.log("get out of msg loop")
except (EOFError, IOError, KeyboardInterrupt):
	pass
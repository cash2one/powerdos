#init imports
import sys
import os

#force root privileges
#euid = os.geteuid()
#if euid != 0:
#	args = ['sudo', sys.executable] + sys.argv + [os.environ]
#	os.execlpe('sudo', *args)

__all__ = [	"color", 
			"mysql"]

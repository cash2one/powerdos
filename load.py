#!/usr/bin/python
from optparse import OptionParser
from multiprocessing.dummy import Pool as ThreadPool 
from threading import Thread
from scapy.all import *
from random import randint
from module import mysql
import MySQLdb, sys, os, socket, signal, time

this = sys.modules[__name__]

def __start(ipList, domainList, threads):
	this.ipList = ipList
	this.domainList = domainList
	this.logFile = open("log/load"+str(time.time())+".log","w")
	this.end = len(this.ipList)
	this.cur = 0
	this.packets = {}
	
	fileName = 'conf/mdb.txt'
	with open(fileName) as lines:
		this.creds = []
		for line in lines:
			line = line.replace('\n', '')
			this.creds.append(line)
	
	pool = ThreadPool(int(threads)) 
	try:
		if this.mode == "dns":
			pool.map_async(__threadDNS, this.ipList).get(9999999)
		else:
			pool.map_async(__threadOther, this.ipList).get(9999999)
	except KeyboardInterrupt:
		print "\n[!] we killed killed all python processes for you"
		os.system('pkill python')
		sys.exit(0)
	pool.close()
	pool.join()
	
	this.logFile.close()

def __sniff(srcPort):
	try:
		this.packets[srcPort] = sniff(filter="udp and port "+str(srcPort), timeout=2)
	except Exception, e:
		print "[!] "+ str(e)
	
def __threadDNS(ip):
	this.cur += 1
	if this.cur % 10 == 0:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(('10.255.255.255', 0))
			con = s.getsockname()[0]
			s.close()
		except:
			print "[!] check your network connection"
			os.system('pkill python')
			sys.exit(0)
	try:
		mdb = MySQLdb.connect(user=this.creds[0],passwd=this.creds[1],host=this.creds[2],db=this.creds[3])
		mdb.autocommit(True)
		cur = mdb.cursor()
	except:
		print "[!] Can't connect to mysql service .."
	floatFactor = 0
	ampDomain = ''
	i=0
	for domain in this.domainList:
		answer = srp(Ether()/IP(dst=ip[0])/UDP(sport=randint(14000,64000),dport=53)/DNS(rd=1,qd=DNSQR(qname=str(domain),qtype="ALL")),timeout=1,verbose=0)
		time.sleep(0.1)
		if len(answer[0]) != 0:
			sendSize = float(len(answer[0][0][0]) +2)
			rcvSize = float(len(answer[0][0][1]) +2)
			tmpFactor = rcvSize / sendSize
			if tmpFactor > floatFactor:
				floatFactor = tmpFactor
				ampDomain = str(domain)
		else:
			if i >= 5 and floatFactor == 0:
				break
		i += 1
	if floatFactor > 2:
		ampFactor = int(floatFactor)
		print "[*] "+str(this.cur)+"/"+str(this.end)+" found server: "+ str(ip[0]) +" with amplification of: "+ str(ampFactor)
		this.logFile.write("[*] found server: "+ str(ip[0]) +" with amplification of: "+ str(ampFactor) +"\n")
		try:
			if this.checkOpt == False:
				cur.execute("INSERT IGNORE INTO amp (ip,dns,dns_quality,dns_domain) VALUES ('"+ str(ip[0]) +"',1,"+ str(ampFactor) +",'"+ str(ampDomain) +"');")
			else:
				cur.execute("UPDATE amp SET ntp_quality="+str(ampFactor)+" WHERE ip='"+str(ip[0])+"';")
		except MySQLdb.Error as e:
			print "[!] "+ str(e)
	elif floatFactor < 2:
		print "[!] "+str(this.cur)+"/"+str(this.end)+" no amplification with: "+ str(ip[0])
		this.logFile.write("[!] no amplification with: "+ str(ip[0]) +"\n")
		try:
			if this.checkOpt == True:
				cur.execute("DELETE FROM amp WHERE ip='"+str(ip[0])+"';")
		except MySQLdb.Error as e:
			print "[!] "+ str(e)
	if this.checkOpt == False:
		try:
			cur.execute("UPDATE public SET `check`=1 WHERE ip='"+ str(ip[0]) +"';")
		except MySQLdb.Error as e:
			print "[!] "+ str(e)
	try:	
		cur.close()
		mdb.close()
	except:
		print "[!] Can't close mysql connection .."
	
def __threadOther(ip):
	try:
		this.cur += 1
		if this.cur % 10 == 0:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				s.connect(('10.255.255.255', 0))
				con = s.getsockname()[0]
				s.close()
			except:
				print "[!] check your network connection"
				os.system('pkill python')
				sys.exit(0)
		try:
			mdb = MySQLdb.connect(user=this.creds[0],passwd=this.creds[1],host=this.creds[2],db=this.creds[3])
			mdb.autocommit(True)
			cur = mdb.cursor()
		except:
			print "[!] Can't connect to mysql service .."
		try:
			srcPort = randint(14000,64000)
			for i in range(0,10):
				if this.packets[srcPort]:
					srcPort = randint(14000,64000)
		except:
			Thread(target = __sniff, args=(srcPort,)).start()
		time.sleep(0.1)
		send(IP(dst=ip[0])/UDP(sport=srcPort,dport=this.port)/Raw(load=this.data1), verbose=0)	
		time.sleep(0.1)
		send(IP(dst=ip[0])/UDP(sport=srcPort,dport=this.port)/Raw(load=this.data1), verbose=0)	
		time.sleep(2)
		ampFactor = 0
		sndB1=0
		rcvB1=0
		sndB2=0
		rcvB2=0
		lenList = []
		if len(this.packets[srcPort]) >2:
			p = 0
			while True:
				try:
					lenList.append(len(this.packets[srcPort][p]))
					p += 1
				except:
					break
			p = 0
			lenListMin = min(lenList)
			while True:
				try:
					if len(this.packets[srcPort][p]) >lenListMin:
						rcvB1 += len(this.packets[srcPort][p])
					elif len(this.packets[srcPort][p]) == lenListMin: 
						sndB1 += len(this.packets[srcPort][p])
					p += 1
				except:
					break
		try:
			this.packets.pop(srcPort)
		except:
			print "[!] list index "+ str(srcPort) +"is empty"
		if this.mode == "ntp":
			try:
				srcPort2 = randint(14000,64000)
				for i in range(0,10):
					if this.packets[srcPort2]:
						srcPort2 = randint(14000,64000)
			except:
				Thread(target = __sniff, args=(srcPort2,)).start()
			time.sleep(0.1)
			send(IP(dst=ip[0])/UDP(sport=srcPort2,dport=this.port)/Raw(load=this.data2), verbose=0)	
			time.sleep(0.1)
			send(IP(dst=ip[0])/UDP(sport=srcPort,dport=this.port)/Raw(load=this.data2), verbose=0)	
			time.sleep(2)
			lenList = []
			if len(this.packets[srcPort2]) >2:
				p = 0
				while True:
					try:
						lenList.append(len(this.packets[srcPort2][p]))
						p += 1
					except:
						break
				p = 0
				lenListMin = min(lenList)
				while True:
					try:
						if len(this.packets[srcPort2][p]) >lenListMin:
							rcvB2 += len(this.packets[srcPort2][p])
						elif len(this.packets[srcPort2][p]) == lenListMin: 
							sndB2 += len(this.packets[srcPort2][p])
						p += 1
					except:
						break
			if rcvB1 != 0 or rcvB2 != 0:
				sndB1 += 32
				rcvB1 += 32
				sndB2 += 32
				rcvB2 += 32
				ampB1 = rcvB1/sndB1
				ampB2 = rcvB2/sndB2
				if ampB1 >= ampB2:	
					ampFactor = ampB1
					ampType = 61
				else:
					ampFactor = ampB2
					ampType = 4
			try:
				this.packets.pop(srcPort2)
			except:
				print "[!] list index "+ str(srcPort2) +"is empty"
		else:
			if rcvB1 != 0 or rcvB2 != 0:
				sndB1 += 16
				rcvB1 += 16
				ampFactor = rcvB1/sndB1
		if ampFactor > 2:
			print "[*] "+str(this.cur)+"/"+str(this.end)+" found server: "+ str(ip[0]) +" with amplification of: "+ str(ampFactor)
			this.logFile.write("[*] found server: "+ str(ip[0]) +" with amplification of: "+ str(ampFactor) +"\n")
			try:
				if this.mode == "ntp":
					cur.execute("INSERT IGNORE INTO amp (ip,ntp,ntp_quality,ntp_data) VALUES ('"+ str(ip[0]) +"',1,"+ str(ampFactor) +","+ str(ampType) +");")
				else:
					cur.execute("INSERT IGNORE INTO amp (ip,"+str(this.mode)+","+str(this.mode)+"_quality) VALUES ('"+ str(ip[0]) +"',1,"+ str(ampFactor) +");")
			except MySQLdb.Error as e:
				print "[!] "+ str(e)
		elif ampFactor < 2:
			print "[!] "+str(this.cur)+"/"+str(this.end)+" no amplification with: "+ str(ip[0])
			this.logFile.write("[!] no amplification with: "+ str(ip[0]) +"\n")
			if this.checkOpt == True:	
				try:
					if this.checkOpt == True:
						cur.execute("DELETE FROM amp WHERE ip='"+str(ip[0])+"';")
				except MySQLdb.Error as e:
					print "[!] "+ str(e)
		if this.checkOpt == False:
			try:
				cur.execute("UPDATE public SET `check`=1 WHERE ip='"+ str(ip[0]) +"';")
			except MySQLdb.Error as e:
				print "[!] "+ str(e)
		try:	
			cur.close()
			mdb.close()
		except:
			print "[!] Can't close mysql connection .."
	except Exception, e:
		print "Failed: "+ str(e)
	
def main():
	parser = OptionParser()
	usage = 'usage: %prog [options]'

	parser.add_option("-s", type="string", metavar="file",
					  help="set source file",
					  dest="source")

	parser.add_option("-d", action="store_false",
					  help="dns mode",
					  dest="dns")
					  
	parser.add_option("-D", default="defcon.org", metavar="file",
					  help="set domain name or file",
					  dest="domain")
					  
	parser.add_option("-n", action="store_false",
					  help="ntp mode",
					  dest="ntp")
					
	parser.add_option("-m", action="store_false",
					  help="snmp mode",
					  dest="snmp")
					  
	parser.add_option("-p", action="store_false",
					  help="ssdp mode",
					  dest="ssdp")
					  
	parser.add_option("-g", action="store_false",
					  help="chargen mode",
					  dest="chargen")
					 
	parser.add_option("-q", action="store_false",
					  help="quake mode",
					  dest="quake")
					  
	parser.add_option("-c", action="store_false",
					  help="check server list again",
					  dest="check")
	
	parser.add_option("-t", metavar="1-32",
					  help="number of threads",
					  dest="threads")

	(options, args) = parser.parse_args()
	
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(('10.255.255.255', 0))
		IP = s.getsockname()[0]
		this.ip = str(IP)
		s.close()
	except:
		print "[!] check your network connection"
		sys.exit(0)
	
	if len(sys.argv[1:]) == 0:
		print "[!] you don't give me an argument"
		parser.print_help()
		sys.exit(0)
	else:
		i=0
		if options.dns == False:
			i+=1
		if options.ntp == False:
			i+=1
		if options.snmp == False:
			i+=1
		if options.ssdp == False:
			i+=1
		if options.chargen == False:
			i+=1
		if options.quake == False:
			i+=1
		
	if i == 1 and options.source:
		try:	
			ipFileRead = open(str(options.source),'r')
			ipList = []
			with ipFileRead as lines:
				for line in lines:
					line = line.replace('\n','')
					if options.dns == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,dns) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT dns FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET dns=1 WHERE ip='"+ str(line) +"';","no")
					elif options.ntp == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,ntp) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT ntp FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET ntp=1 WHERE ip='"+ str(line) +"';","no")
					elif options.snmp == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,snmp) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT snmp FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET snmp=1 WHERE ip='"+ str(line) +"';","no")
					elif options.ssdp == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,ssdp) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT ssdp FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET ssdp=1 WHERE ip='"+ str(line) +"';","no")
					elif options.chargen == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,chargen) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT chargen FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET chargen=1 WHERE ip='"+ str(line) +"';","no")
					elif options.quake == False:
						mysql.executeSQL("INSERT IGNORE INTO public (ip,quake) VALUES ('"+ str(line) +"',1);","no")
						e = mysql.executeSQL("SELECT quake FROM public WHERE ip='"+ str(line) +"';","one")
						if str(e[0]) == "0":
							mysql.executeSQL("UPDATE public SET quake=1 WHERE ip='"+ str(line) +"';","no")
			ipFileRead.close()
		except Exception, e:
			print "[!] invalid argument" + str(e)		
	elif i == 1:
		try:
			domainList = []
			if '.TXT' in options.domain.upper():
				domainFileRead = open(str(options.domain),'r')
				with domainFileRead as lines:
					for line in lines:
						line = line.replace('\n','')
						domainList.append(line)	
				domainFileRead.close()
			else:
				domainList.append(str(options.domain))		
		except:
			print "[!] somethings is wrong with the specified sourcefile"
			
		PAYLOAD = {
			'snmp':('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
				'\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
				'\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
				'\x01\x02\x01\x05\x00'),
			'ntp1':('\x17\x00\x02\x2a'+'\x00'*4),
			'ntp2':('\x17\x00\x03\x2a'+'\x00'*61),
			'chargen':('0'),
			'quake':('\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10'),
			'ssdp':('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
				'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
		}	
			
		this.checkOpt = False
		if options.dns == False:
			this.mode = "dns"
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND dns=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE dns=1;","all")
		elif options.ntp == False:
			this.mode = "ntp"
			this.port = 123
			this.data1 = PAYLOAD['ntp2']
			this.data2 = PAYLOAD['ntp1']
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND ntp=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE ntp=1;","all")
		elif options.snmp == False:
			this.mode = "snmp"
			this.port = 161
			this.data1 = PAYLOAD['snmp']
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND snmp=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE snmp=1;","all")
		elif options.ssdp == False:
			this.mode = "ssdp"
			this.port = 1900
			this.data1 = PAYLOAD['ssdp']
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND ssdp=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE ssdp=1;","all")
		elif options.chargen == False:
			this.mode = "chargen"
			this.port = 19
			this.data1 = PAYLOAD['chargen']
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND chargen=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE chargen=1;","all")
		elif options.quake == False:
			this.mode = "quake"
			this.port = 27960
			this.data1 = PAYLOAD['quake']
			if options.check != False:
				ipList = mysql.executeSQL("SELECT ip FROM public WHERE `check`=0 AND quake=1;","all")
			else:
				this.checkOpt = True
				ipList = mysql.executeSQL("SELECT ip FROM amp WHERE quake=1;","all")
		
		if options.threads:
			__start(ipList, domainList, str(options.threads))
		else:
			__start(ipList, domainList, "1")
	else:
		print "[!] invalid argument"
		parser.print_help()
		sys.exit(0)
	
if __name__=='__main__':
	main()

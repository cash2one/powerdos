#mysql module

import MySQLdb
import sys
import time
import re

this = sys.modules[__name__] 
this.mdb = False
this.cur = False

def dbConnect():
	try:
		fileName = './conf/mdb.txt'
		with open(fileName) as lines:
			creds = []
			for line in lines:
				line = line.replace('\n', '')
				creds.append(line)
		
		if str(creds[0]).isalnum() == True:
			user = str(creds[0])
		else:
			print "[!] Username is not alphanumeric .."
		
		passwd = str(creds[1])
		passwd = re.sub('[^0-9A-Za-z,.;:-_><|#+\*\\?=)(/&%$!{[]}@]', '', passwd)
		
		host = str(creds[2])
		host = re.sub('[^0-9\.]', '', host)
		
		if str(creds[3]).isalnum() == True:
			db = str(creds[3])
		else:
			print "[!] Database name is not alphanumeric .."
			
		this.mdb = MySQLdb.connect(
			user=user,
			passwd=passwd,
			host=host,
			db=db)
			
		this.mdb.autocommit(True)
		this.cur = mdb.cursor()
			
		return this.mdb, this.cur
	except:
		print "[!] Can't connect to Mysql service .."
		quit()
		
def dbClose():
	this.cur[1].close()
	this.mdb.close()
	
def executeSQL(sql, fetch):
	this.cur = dbConnect()
	
	try:
		this.cur[1].execute(sql)
		if fetch == "one":
			data = this.cur[1].fetchone()
		elif fetch == "all":
			data = this.cur[1].fetchall()
		elif fetch == "no":
			data = True
		dbClose()
		
		return data
	except Exception as e:
		print "[!] "+ str(e)
		time.sleep(10)
		
		return False

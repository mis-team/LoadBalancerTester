#!/usr/bin/env python2

import glob
import psutil
import os
import time
import optparse
import requests
import collections
import urllib3
import threading
urllib3.disable_warnings()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


endpoints=collections.defaultdict(dict)
results=collections.defaultdict(dict)
config = {'timeout':2,
		  'useragent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3191.0 Safari/537.36',
		  'redirects':False,
		  'debug':False,
		  'proxy':{}}

def initial_curl(domain, conf):
	#curling http
	try:
		r80 = requests.get('http://' + domain, allow_redirects=conf['redirects'], timeout=conf['timeout'],headers={'User-Agent':conf['useragent']}, proxies=conf['proxy'])
		endpoints[domain]['httpcode'] = r80.status_code
		endpoints[domain]['httpsize'] = str(len(r80.content))
	except requests.exceptions.RequestException as e:
		# print e
		if conf['debug']:
			print "Debug: " + domain + " exception"
		#endpoints[domain]['httpcode'] = 'X'
		#endpoints[domain]['httpsize'] = 0
	#curling https
	try:
		r443 = requests.get('https://' + domain, allow_redirects=conf['redirects'], timeout=conf['timeout'], verify=False,headers={'User-Agent':conf['useragent']}, proxies=conf['proxy'])
		endpoints[domain]['httpscode'] = r443.status_code
		endpoints[domain]['httpssize'] = str(len(r443.content))
	except requests.exceptions.RequestException as e:
		# print e
		if conf['debug']:
			print "Debug: " + domain + " exception"
		#endpoints[domain]['httpscode'] = 'X'
		#endpoints[domain]['httpssize'] = 0
	return None


def worker(domain, domainslist, conf):
	domain = domain.rstrip('\n')
	print "Checking " + domain + "..."

	for host in domainslist:
		host = host.rstrip('\n')
		try:
			r80 = requests.get('http://' + domain, allow_redirects=conf['redirects'], timeout=conf['timeout'], headers={'Host': host,'User-Agent':conf['useragent']}, proxies=conf['proxy'])
			results[domain][host]["httpcode"] = r80.status_code
			results[domain][host]["httpsize"] = str(len(r80.content))
		except requests.exceptions.RequestException as e:
			# print e
			if conf['debug']:
				print "Debug: Exception " + domain + " with hostname " + host+". Exception: "+str(e)
			#print ". size: "+str(len(r80.content))+", code: "+str(r80.status_code)
		try:
			r443 = requests.get('https://' + domain, verify=False, allow_redirects=conf['redirects'],
								timeout=conf['timeout'], headers={'Host': host, 'User-Agent': conf['useragent']},
								proxies=conf['proxy'])
			results[domain][host]["httpscode"] = r443.status_code
			results[domain][host]["httpssize"] = str(len(r443.content))
		except requests.exceptions.RequestException as e:
			if conf['debug']:
				print "Debug: Exception " + domain + " with hostname " + host+". Exception: "+str(e)

	return None

def main():

	#setting args
	if 1 > 0:
		print "Load balancers testing multithreading script. Tries to connect each domain with different Host header and compares results. Use -h for usage"
		parser = optparse.OptionParser(usage="usage: %prog [options] filename",version="%prog 1.0")

		parser.add_option("-d", "--domainsfile", type="string", help="domain names file", action="store", dest="domainsfile")
		parser.add_option("", "--hs", type="string", help="Do not show size filter", action="store",dest="sizefilter")
		parser.add_option("", "--hc", type="string", help="Do not show code filter", action="store", dest="codefilter")
		parser.add_option("-A", "--user-agent", type="string", help="User-Agents string", action="store", dest="useragent")
		parser.add_option("-p", "--proxy", type="string", help="proxy in http://127.0.0.1:8080 format", action="store", dest="proxy")
		parser.add_option("", "--xf", help="Filter exceptions", action="store_true", dest="exfilter")
		parser.add_option("", "--debug", help="Debug messages", action="store_true", dest="debug")
		parser.add_option("-t", "--threads", type="int", help="Threads limit", action="store", dest="threads")
		parser.add_option("", "--timeout", type="int", help="Request timeout in sec", action="store", dest="timeout")
		parser.add_option("-f", "--follow", help="Request follow redirectons", action="store_true", dest="follow")

		(args, _) = parser.parse_args()

		#print args
		if args.sizefilter:
			sizefilter = args.sizefilter
		else:
			sizefilter = 0

		if args.codefilter:
			codefilter = args.codefilter
		else:
			codefilter = 0

		if args.threads:
			threadslim = args.threads
		else:
			threadslim = 0

		if args.useragent:
			config['useragent']=args.useragent

		if args.follow:
			config['redirects']=True

		if args.debug:
			config['debug']=True

		if args.timeout:
			config['timeout']=args.timeout

		if args.proxy:
			config['proxy']={'http':args.proxy,'https':args.proxy}


		if args.domainsfile:
			#with open(args.domainsfile) as f:
			#	domains = f.readlines()

			domains = [line.rstrip('\n') for line in open(args.domainsfile)]
		else:
			print "Use -h for usage"
			exit()


	#preparing endpoints and results dict
	for domain in domains:
		domain = domain.rstrip('\n')
		endpoints[domain]['httpcode'] = 'X'
		endpoints[domain]['httpsize'] = "0"
		endpoints[domain]['httpscode'] = 'X'
		endpoints[domain]['httpssize'] = "0"

		results[domain] = {}
		for hosts in domains:
			hosts = hosts.rstrip('\n')
			results[domain][hosts] = {}
			results[domain][hosts]['httpcode'] = 'X'
			results[domain][hosts]['httpsize'] = "0"
			results[domain][hosts]['httpscode'] = 'X'
			results[domain][hosts]['httpssize'] = "0"

	print "Doing http checks initial.."
	threads = []

	#get normal threads num (because debugger...)
	threadsnum = threading.activeCount()
	print "Debug: threadsnum is "+str(threadsnum)

	for domain in domains:
		domain = domain.rstrip('\n')
		t = threading.Thread(target=initial_curl,args=(domain,config))
		threads.append(t)
		if threadslim > 0:
			while threading.activeCount() > threadslim + threadsnum:
				#wait while some threads finished
				#print "threads limit waiting.."+str(threading.activeCount())+" - "+str(threadslim + threadsnum)
				time.sleep(0.1)
		t.start()

	for t in threads:
		t.join()

	if args.exfilter:
		#removing hosts with X code
		for domain in domains:
			if endpoints[domain]['httpcode'] == "X" and endpoints[domain]['httpscode'] == "X":
				#del endpoints[domain]
				domains.remove(domain)

	print "Initial results:"
	template = "{0:38}|{1:15}|{2:15}|{3:15}|{4:15}|"  # column widths:
	print template.format("Domain", "http code", "http size", "httpS code", "httpS size")
	print "-------------------------------------------------------------------------------------------------------"
	for domain in domains:
		domain = domain.rstrip('\n')
		print template.format(domain,"    "+str(endpoints[domain]['httpcode']),"    "+str(endpoints[domain]['httpsize']),"    "+str(endpoints[domain]['httpscode']),"    "+str(endpoints[domain]['httpssize']))



	print("Start checking with %d threads maximum"%(threadslim))
	threads = []
	# get normal threads num (because debugger...)
	threadsnum = threading.activeCount()

	for domain in domains:
		domain = domain.rstrip('\n')
		#print "Checking "+domain+"..."
		t = threading.Thread(target=worker,args=(domain,results,config))
		threads.append(t)
		if threadslim > 0:
			while threading.activeCount() > threadslim + threadsnum:
				#wait while some threads finished
				time.sleep(0.1)
		t.start()

	#wait for all threads finish
	for t in threads:
		t.join()

	print "Checking done"
	print "\n================================================"
	print "Results:"

	#print in plaintext
	for domain in domains:
		print "\nDomain: "+domain
		template = "{0:38}|{1:15}|{2:15}|{3:15}|{4:15}|"  # column widths:
		print template.format(bcolors.ENDC+"Host", "http code", "http size", "httpS code", "httpS size")
		template = "{0:39}|{1:15}|{2:15}|{3:15}|{4:15}|"  # column widths:
		print "-------------------------------------------------------------------------------------------------------"
		print template.format(bcolors.OKGREEN+domain+"          ", str(results[domain][domain]['httpcode']), str(results[domain][domain]['httpsize']),
							  str(results[domain][domain]['httpscode']), str(results[domain][domain]['httpssize']))
		for host in results:
			color = bcolors.ENDC
			template = "{0:38}|{1:15}|{2:15}|{3:15}|{4:15}|"+bcolors.ENDC  # column widths:
			if host != domain:
				if (endpoints[domain]['httpcode'] != results[domain][host]['httpcode']):
					if (codefilter == 0) or (
							(codefilter > 0) and (str(results[domain][host]['httpcode']) != str(codefilter))):
						color = bcolors.FAIL
						template = "{0:39}|{1:15}|{2:15}|{3:15}|{4:15}|"+bcolors.ENDC # column widths:
				if (endpoints[domain]['httpscode'] != results[domain][host]['httpscode']):
					if (codefilter == 0) or (
							(codefilter > 0) and (str(results[domain][host]['httpscode']) != str(codefilter))):
						color = bcolors.FAIL
						template = "{0:39}|{1:15}|{2:15}|{3:15}|{4:15}|"+bcolors.ENDC  # column widths:
				print template.format(color+host,str(results[domain][host]['httpcode']),str(results[domain][host]['httpsize']),str(results[domain][host]['httpscode']),str(results[domain][host]['httpssize']))


		if config['debug']:
			# print results in json
			print "Debig: raw: "
			print results[domain]
		'''
		if (endpoints[domain]['httpcode'] != results[domain][host]['httpcode']):
			if (codefilter == 0) or ((codefilter > 0) and (str(results[domain][host]['httpcode']) != str(codefilter))):
				print "other code: " + domain + " with hostname " + host + ". Code: " + str(
					results[domain][host]['httpcode']) + ". Orig: " + str(endpoints[domain]['httpcode'])
		if (endpoints[domain]['httpscode'] != results[domain][host]['httpscode']):
			if (codefilter == 0) or ((codefilter > 0) and (str(results[domain][host]['httpscode']) != str(codefilter))):
				print "other code: " + domain + " with hostname " + host + ". Code: " + str(
					results[domain][host]['httpscode']) + ". Orig: " + str(endpoints[domain]['httpscode'])
		'''

	'''
	for domain in domains:
		for host in results:
			if (endpoints[domain]['httpcode'] != results[domain][host]['httpcode']):
				if (codefilter == 0) or ((codefilter > 0) and (str(results[domain][host]['httpcode']) != str(codefilter))):
					print "other code: " + domain + " with hostname " + host + ". Code: " + str(results[domain][host]['httpcode']) + ". Orig: " + str(endpoints[domain]['httpcode'])
			if (endpoints[domain]['httpscode'] != results[domain][host]['httpscode']):
				if (codefilter == 0) or ((codefilter > 0) and (str(results[domain][host]['httpscode']) != str(codefilter))):
					print "other code: " + domain + " with hostname " + host + ". Code: " + str(results[domain][host]['httpscode']) + ". Orig: " + str(endpoints[domain]['httpscode'])
	'''
	return None

				

if __name__ == '__main__':
    main()
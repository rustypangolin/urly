#!/usr/bin/python3

import sys
from tld import get_fld
from tld.utils import update_tld_names
import argparse
import ipaddress
import logging
import requests
from bs4 import BeautifulSoup
import re

def main():
	parser = argparse.ArgumentParser(description='Get threat intel on a hostname, IP using widely available sources.')
	parser.add_argument('data', metavar='host', help='hostname or IP to check')
	#parser.add_argument('--bulk', action='store_true', help='specify if you want to read a file list of hosts to scan')
	#parser.add_argument('--local', action='store_true', help='only query local db')
	parser.add_argument('--refresh-domains', action='store_true', help='force domain refresh for get_fld')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('--v', action='store_true', help='enable verbosity')
	group.add_argument('--q', action='store_true', help='enable quiet mode')

	args = parser.parse_args()

	setLogging(args.v, args.q)
	isIP = checkIP(args.data)

	if isIP == False:
		checkDomain(args.data, args.refresh_domains)
	elif isIP == True:
		logging.info('ip!')
		ipVoidResults = ipVoid(args.data)
		if ipVoidResults:
			logging.info('IP Address Information:')
			logging.warning('Result: ' + ipVoidResults[7])
			logging.info('Scan date: ' + ipVoidResults[0])
			logging.info('IP: ' + ipVoidResults[1])
			logging.info('Reverse DNS: ' + ipVoidResults[2])
			logging.info('ASN: ' + ipVoidResults[3])
			logging.info('ASN Owner: ' + ipVoidResults[4])
			logging.info('ISP: ' + ipVoidResults[5])
			logging.info('Country: ' + ipVoidResults[6])

			if ipVoidResults[8] > 0:
				logging.info('Detected on the following engines:')
				for i in ipVoidResults[9]:
					logging.info('-' + i)

def checkDomain(data, refresh):
	if refresh == True:
		logging.debug('Refreshing TLD database.')
		update_tld_names()
	try:
		logging.warning(get_fld(data, fix_protocol=True))
	except Exception as e:
		logging.warning(e)
		sys.exit(0)

def checkIP(data):
	logging.debug('Checking if the input is an IP address.')
	isIP = True

	try:
		ipaddress.ip_address(data)
		logging.debug('Input is an IP address.')
	except ValueError as e:
			isIP = False
			logging.debug('Input is not an IP address.')

	if isIP == True:
		if ipaddress.ip_address(data).is_private == True:
			logging.warning('Private IP detected, terminating.')
			sys.exit(0)

	return isIP

def ipVoid(data):
	r = requests.post('http://www.ipvoid.com/ip-blacklist-check/', data = {'ip': data})
	soup = BeautifulSoup(r.text, 'html.parser')
	aDateRow = soup.find_all('tr')[0]
	aDate = aDateRow.find_all('td')[1].text

	aIPRow = soup.find_all('tr')[3]
	aIP = aIPRow.find_all('strong')[0].text

	aRevRow = soup.find_all('tr')[4]
	aRev = aRevRow.find_all('td')[1].text

	aASNRow = soup.find_all('tr')[5]
	aASN = aASNRow.find_all('a')[0].text

	aASNOwnerRow = soup.find_all('tr')[6]
	aASNOwner = aASNOwnerRow.find_all('td')[1].text

	aISPRow = soup.find_all('tr')[7]
	aISP = aISPRow.find_all('td')[1].text

	aCountryRow = soup.find_all('tr')[9]
	aCountry = aCountryRow.find_all('td')[1].text

	aStatus = soup.find('span', class_='label label-warning').text

	detectionCount = re.search('BLACKLISTED (.+?)/', aStatus)
	if detectionCount:
		detectionList = ipVoidLists(soup, detectionCount.group(1))
	return aDate, aIP, aRev, aASN, aASNOwner, aISP, aCountry, aStatus, int(detectionCount.group(1)), detectionList

def ipVoidLists(data, count):
	detectionList=[]

	aDetections = data.find_all('table', class_='table table-striped table-bordered')[1]

	for i in range(int(count)):
		detectionList.append(aDetections.find_all('td')[i].text)
	return detectionList

def setLogging(verbosity, quiet):
	logFormat = '%(message)s'
	if verbosity == True:
		logging.basicConfig(format=logFormat, level=logging.DEBUG)
	elif quiet == True:
		logging.basicConfig(format=logFormat, level=logging.WARNING)
	else:
		logging.basicConfig(format=logFormat, level=logging.INFO)

if __name__ == "__main__":
	main()

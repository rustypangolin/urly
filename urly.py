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
		logging.debug('domain!')
		domain = checkDomain(args.data, args.refresh_domains)
		urlVoidResults = urlVoid(domain)

		if urlVoidResults:
			if urlVoidResults[8] > 0:
				status = 'BLACKLISTED'
			else:
				status = 'POSSIBLY SAFE'
			logging.info('\nHostname Information:')
			logging.warning('Result: ' + status + ' ' + urlVoidResults[2])
			logging.info('Scan date: ' + urlVoidResults[0])
			logging.info('Hostname: ' + urlVoidResults[1])
			logging.info('IP: ' + urlVoidResults[3])
			logging.info('Reverse DNS: ' + urlVoidResults[4])
			logging.info('Domain age: ' + urlVoidResults[5])
			logging.info('ASN: ' + urlVoidResults[6])
			logging.info('Country: ' + urlVoidResults[7])

			if urlVoidResults[8] > 0:
				logging.info('\nDetected on the following engines:')
				for i in urlVoidResults[9]:
					logging.info('-' + i)

	elif isIP == True:
		logging.debug('ip!')
		ipVoidResults = ipVoid(args.data)
		if ipVoidResults:
			logging.info('\nIP Address Information:')
			logging.warning('Result: ' + ipVoidResults[7])
			logging.info('Scan date: ' + ipVoidResults[0])
			logging.info('IP: ' + ipVoidResults[1])
			logging.info('Reverse DNS: ' + ipVoidResults[2])
			logging.info('ASN: ' + ipVoidResults[3])
			logging.info('ASN Owner: ' + ipVoidResults[4])
			logging.info('ISP: ' + ipVoidResults[5])
			logging.info('Country: ' + ipVoidResults[6])

			if ipVoidResults[8] > 0:
				logging.info('\nDetected on the following engines:')
				for i in ipVoidResults[9]:
					logging.info('-' + i)

def checkDomain(data, refresh):
	if refresh == True:
		logging.debug('Refreshing TLD database.')
		update_tld_names()
	try:
		domain = get_fld(data, fix_protocol=True)
	except Exception as e:
		logging.warning(e)
		sys.exit(0)
	return domain

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

	aDate = soup.find_all('tr')[0].find_all('td')[1].text
	aIP = soup.find_all('tr')[3].find_all('strong')[0].text
	aRev = soup.find_all('tr')[4].find_all('td')[1].text
	aASN = soup.find_all('tr')[5].find_all('a')[0].text
	aASNOwner = soup.find_all('tr')[6].find_all('td')[1].text
	aISP = soup.find_all('tr')[7].find_all('td')[1].text
	aCountry = soup.find_all('tr')[9].find_all('td')[1].text
	aStatus = soup.find('span', class_='label label-warning').text

	detectionCount = re.search('BLACKLISTED (.+?)/', aStatus)
	if detectionCount:
		detectionList = ipVoidLists(soup, detectionCount.group(1))
	else:
		detectionList = []
	return aDate, aIP, aRev, aASN, aASNOwner, aISP, aCountry, aStatus, int(detectionCount.group(1)), detectionList

def ipVoidLists(data, count):
	detectionList = []

	aDetections = data.find_all('table', class_='table table-striped table-bordered')[1]

	for i in range(int(count)):
		detectionList.append(aDetections.find_all('td')[i].text)
	return detectionList

def urlVoid(data):
	r = requests.get('https://www.urlvoid.com/scan/' + data)
	soup = BeautifulSoup(r.text, 'html.parser')

	table = soup.find_all("table")[0]
	aDate = re.search('(.*)\|.*', table.find_all('tr')[1].find_all('td')[1].text)
	aStatus = table.find_all('tr')[2].find_all('td')[1].text
	aDomainAge = table.find_all('tr')[3].find_all('td')[1].text
	aIP = table.find_all('tr')[5].find_all('td')[1].find('strong').text
	aRev = table.find_all('tr')[6].find_all('td')[1].text
	aASN = table.find_all('tr')[7].find_all('td')[1].text
	aCountry = table.find_all('tr')[8].find_all('td')[1].text

	detectionCount = re.search('(.+?)/', aStatus)
	if detectionCount:
		detectionList = urlVoidLists(soup, detectionCount.group(1))
	else:
		detectionList = []

	return aDate.group(1), data, aStatus, aIP, aRev, aDomainAge, aASN, aCountry, int(detectionCount.group(1)), detectionList

def urlVoidLists(data, count):
	detectionList = []

	aDetections = data.find_all('table', class_='table table-custom table-striped')[1]

	for i in range(1,int(count)+1):
		detectionList.append(aDetections.find_all('tr')[i].find_all('td')[0].text)
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

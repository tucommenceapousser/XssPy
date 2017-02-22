import mechanize
import sys
import httplib
import argparse
import logging
from urlparse import urlparse

br = mechanize.Browser()	#initiating the browser
br.addheaders = [('User-agent', 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11)Gecko/20071127 Firefox/2.0.0.11')]
br.set_handle_robots(False)
br.set_handle_refresh(False)


class color:
   RED = '\033[91m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   BOLD = '\033[1m'
   END = '\033[0m'
   @staticmethod
   def log(lvl, col, msg):
       logger.log(lvl, col + msg + color.END)

print color.BOLD + color.RED + """
XssPy - Finding XSS made easier
Author: Faizan Ahmad (Fsecurify)
Email: fsecurify@gmail.com
Usage: pythonXssPy.py website.com (Do not write www.website.com OR http://www.website.com)
Comprehensive Scan: python XssPy.py website.com -e

Description: XssPy is a python tool for finding Cross Site Scripting 
vulnerabilities in websites. This tool is the first of its kind.
Instead of just checking one page as most of the tools do, this tool 
traverses the website and find all the links and subdomains first.
After that, it starts scanning each and every input on each and every
 page that it found while its traversal. It uses small yet effective
payloads to search for XSS vulnerabilities. XSS in many high
profile websites and educational institutes has been found
by using this very tool.
""" + color.END

logger = logging.getLogger(__name__)
lh = logging.StreamHandler()  # Handler for the logger
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)

parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url', help='The URL to analyze')
parser.add_argument('-e', action='store_true', dest='compOn', help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='verbose', help='Enable verbose logging')
results = parser.parse_args()

logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)

def initializeAndFind(firstDomains):

	dummy = 0	#dummy variable for doing nothing
	firstDomains = []	#list of domains
	if not results.url:	#if the url has been passed or not
	    color.log(logging.INFO, color.GREEN, 'Url not provided correctly')
	    return 0
	
	smallurl = results.url	#small url is the part of url without http and www

	allURLS = []
	allURLS.append(smallurl)	#just one url at the moment
	largeNumberOfUrls = []	#in case one wants to do comprehensive search

        color.log(logging.INFO, color.GREEN, 'Doing a short traversal.')	#doing a short traversal if no command line argument is being passed
        for url in allURLS:
                x = str(url)
                smallurl = x

                try:	# Test HTTPS/HTTP compatibility. Prefers HTTPS but defaults to HTTP if any errors are encountered
                        test = httplib.HTTPSConnection(smallurl)
                        test.request("GET", "/")
                        response = test.getresponse()
                        if (response.status == 200) | (response.status == 302):
                                url = "https://www." + str(url)
                        elif response.status == 301:
                                loc = response.getheader('Location')
                                url = loc.scheme + '://' + loc.netloc
                        else:
                                url = "http://www." + str(url)
                except:
                                url = "http://www." + str(url)

                try:
                        br.open(url)
                        color.log(logging.INFO, color.GREEN, 'Finding all the links of the website ' + str(url))
                        try:
                                for link in br.links():		#finding the links of the website
                                        if smallurl in str(link.absolute_url):
                                                firstDomains.append(str(link.absolute_url))
                                firstDomains = list(set(firstDomains))
                        except:
                                dummy = 0
                except:
                        dummy = 0
        color.log(logging.INFO, color.GREEN, 'Number of links to test are: ' + str(len(firstDomains)))
		
	if results.compOn:
                color.log(logging.INFO, color.GREEN, 'Doing a comprehensive traversal. This could take a while')
                for link in firstDomains:
                        try:
                                br.open(link)
                                try:
                                        for newlink in br.links():	#going deeper into each link and finding its links
                                                if smallurl in str(newlink.absolute_url):
                                                        largeNumberOfUrls.append(newlink.absolute_url)
                                except:
                                        dummy = 0
                        except:
                                dummy = 0

                firstDomains = list(set(firstDomains + largeNumberOfUrls))
                color.log(logging.INFO, color.GREEN, 'Total Number of links to test have become: ' + str(len(firstDomains)))	#all links have been found
	return firstDomains


def findxss(firstDomains):
	color.log(logging.INFO, color.GREEN, 'Started finding XSS')	#starting finding XSS
	xssLinks = []			#TOTAL CROSS SITE SCRIPTING FINDINGS
	count = 0			#to check for forms
	dummyVar = 0			#dummy variable for doing nothing
	if len(firstDomains) > 0:	#if there is atleast one link
		for link in firstDomains:
			y = str(link)
			color.log(logging.DEBUG, color.YELLOW, str(link))
			if 'jpg' in y:		#just a small check
				color.log(logging.DEBUG, color.RED, '\tNot a good url to test')
			elif 'pdf' in y:
				color.log(logging.DEBUG, color.RED, '\tNot a good url to test')
			else:
				try:
					br.open(str(link))	#open the link
				except:
					dummyVar = 0
				try:
					for form in br.forms():	#check its forms
						count = count + 1
				except:
					dummyVar = 0
				if count > 0:		#if a form exists, submit it
					try:
						params = list(br.forms())[0]	#our form
					except:
						dummyVar = 0
					try:
						br.select_form(nr=0)	#submit the first form
					except:
						dummyVar = 0
					for p in params.controls:
						par = str(p)
						if 'TextControl' in par:		#submit only those forms which require text
                                                    color.log(logging.DEBUG, color.YELLOW, '\tParam: ' + str(p.name))
                                                    try:
                                                            br.form[str(p.name)] = '<svg "ons>'		#our payload
                                                    except:
                                                            dummyVar = 0
                                                    try:
                                                            br.submit()
                                                    except:
                                                            dummyVar = 0
                                                    try:
                                                            if '<svg "ons>' in br.response().read():	#if payload is found in response, we have XSS
                                                                    color.log(logging.INFO, color.BOLD+color.GREEN, 'Xss found and the link is ' + str(link) + ' And the payload is <svg \"ons>')
                                                                    xssLinks.append(link)
                                                            else:
                                                                    dummyVar = 0
                                                    except:
                                                            color.log(logging.INFO, color.RED, '\tcould not read the page')
                                                    try:
                                                            br.back()
                                                    except:
                                                            dummyVar = 0

                                                    #SECOND PAYLOAD

                                                    try:
                                                            br.form[str(p.name)] = 'javascript:alert(1)'	#second payload
                                                    except:
                                                            dummyVar = 0
                                                    try:
                                                            br.submit()
                                                    except:
                                                            dummyVar = 0
                                                    try:
                                                            if '<a href="javascript:alert(1)' in br.response().read():
                                                                    color.log(logging.INFO, 'Xss found and the link is ' + str(link) + ' And the payload is javascript:alert(1)')
                                                                    xssLinks.append(link)
                                                            else:
                                                                    dummyVar = 0
                                                    except:
                                                            color.log(logging.INFO, color.RED, '\tCould not read a page')
                                                    try:
                                                            br.back()		#go back to the previous page
                                                    except:
                                                            dummyVar = 0
                                                count = 0
                color.log(logging.DEBUG, color.GREEN+color.BOLD, 'The following links are vulnerable: ')
                for link in xssLinks:		#print all xss findings
			color.log(logging.DEBUG, color.GREEN, '\t'+link)
	else:
		color.log(logging.INFO, color.RED+color.BOLD, '\tNo link found, exiting')

#calling the function
firstDomains = []
firstDomains = initializeAndFind(firstDomains)
findxss(firstDomains)

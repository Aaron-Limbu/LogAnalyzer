import re
from colorama import Fore, init    
import argparse
#weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326'

#weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /.env HTTP/1.1" 200 2326'

nlog = '192.168.1.24 - - [02/Sep/2026:14:32:01 +0000] "GET / HTTP/1.1" 200 8241 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36"'
slog = '192.168.1.45 - - [02/Sep/2026:14:32:10 +0000] "GET /.env HTTP/1.1" 200 4526 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"'

entry = {
    "ip":[],
    "date":[],
    "content":[],
    "status":[],
    "useragent":[],
    "referrer_url":[],
}

LogTable = []
"""
    For analyzing weblog i create list of files or path to files for checking what is being accessed 
    rather than this writing every path to sensitive file for find it on log i will just use extensions like .conf .log 
    now for testing other cases other weblog list will be used. :)
    this program will be taking weblog from log file passed from main.py later on 
"""

# normal 
norm = ['192.168.1.50 - - [21/Aug/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 4523'
,'10.0.0.12 - - [21/Aug/2026:10:16:02 +0000] "GET /static/css/main.css HTTP/1.1" 200 12540',
'172.16.0.5 - - [21/Aug/2026:10:17:11 +0000] "POST /api/v1/login HTTP/1.1" 200 342',
'192.168.1.75 - - [21/Aug/2026:10:18:00 +0000] "GET /images/logo.png HTTP/1.1" 304 0']


# malicious scans & recons 
mr = ['185.220.101.5 - - [22/Aug/2026:01:22:14 +0000] "GET /wp-admin/ HTTP/1.1" 404 1245',
'45.155.205.23 - - [22/Aug/2026:02:45:10 +0000] "GET /config.php HTTP/1.1" 404 1245',
'91.241.19.82 - - [22/Aug/2026:03:12:00 +0000] "POST /xmlrpc.php HTTP/1.1" 403 220',
'141.98.11.44 - - [22/Aug/2026:04:05:19 +0000] "GET /shell?cd+/tmp;rm+-rf+*;wget+... HTTP/1.1" 400 312']

# client & server errors
cserror = [
        '192.168.1.100 - - [22/Aug/2026:14:20:05 +0000] "GET /bad-link HTTP/1.1" 404 1245',
        '172.217.16.142 - - [22/Aug/2026:15:32:41 +0000] "POST /checkout HTTP/1.1" 500 562',
        '10.0.0.5 - - [22/Aug/2026:16:01:12 +0000] "GET /heavy-report HTTP/1.1" 504 0'
]


not_good = [
    '.env',
    'storage/laravel.log'
]

status_codes = [
    '200',"404","304","403","404","500"
]

badf_ext = [
    '.env',
    '.log',
    '.txt',
    '.ini',
]


protectedDir = [
    '/admin/',
    '/wp-admin/',
    '/storage/',
    '/packages/',
    '/vendor/',
    '/bootstrap/',
    '/cache/',
    '/database/',
    '/config/',
    '/app/',
    '/routes/'
]

goodf_ext = [
    '.html',
    '.php',
    '.png',
    '.css',
]

protectedFiles = [
    'config',
    'composer.json',
    'composer.lock',
    '.git',
    'xmlrpc.php'
]

rce_cmds = [
    'cd',
    'rm',
    'cat',
    'ls',
]

common_endpoints = [
    '/checkout',
    '/heavy-report',
]

api_endpoints = [
    '/api/v1/login',
]



class LogAnalyzer: 
    def __init__(self,weblog,table):
        self.weblog = weblog
        self.table = table

    def analyzeLog(self):
        ip_pattern = r"\b\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        found_ip = re.findall(ip_pattern,self.weblog)
        
        for ip in found_ip:
            print(f"[+] ip found : {ip}")
            self.table["ip"].append(ip)

        date_pattern = r"\[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]"        
        found_date = []
        matched = re.search(date_pattern,self.weblog)
        found_date.append(matched.group())
        for date in found_date: 
            print(f"[+] date: {date}")
            self.table["date"].append(date)
        self.analyzeReq()

        
    def getReqAnalyze(self,status,request_line):
        reason = {
            "sus_dir": lambda sd: print(Fore.RED + f"[!] Suspicious Request for Directory : {sd}"),
            "sus_file": lambda sf: print(Fore.RED + f"[!] Suspicious Request for File : {sf}"),
            "coserror": lambda ep: print(Fore.YELLOW + f"[-] Server Error endpoint : {ep}"),
            "cmd_found":  lambda cmd: print(Fore.RED + f"[!] Command Found : {cmd}")
        }
        b_status = {"404","500","504"}

        defaultcheck = re.search(r'\b\s/\s\b',request_line)
        if defaultcheck:
            print(f"[+] Normal Request : {defaultcheck.group()}")
            
            
        if (status.group().strip() in b_status) and (request_line.split()[1] not in common_endpoints):
            reason.get("coserror",lambda ep: "[-] Not Found")(request_line.split()[1])

        if f_match := next((n for n in badf_ext if n in request_line),None):
            reason.get("sus_file",lambda sf: "[-] Not Found")(f_match)
        else:
            if dir_match := next((di for di in protectedDir if di in request_line),None):
                reason.get("sus_dir", lambda sd: "[-] Not Found")(dir_match)

            if ce_match := next((cmd for cmd in rce_cmds if cmd in request_line),None):
                reason.get("cmd_found", lambda cmd: "[-] Not Found")(ce_match)

            if e_match := next((e for e in common_endpoints if e in request_line),None):
                if status.group().strip() in b_status:
                    reason.get("coserror",lambda ep : "[-] Not Found")(e_match)
                    
            if f_match := next((g for g in goodf_ext if g in request_line),None):
                
                if fp_match := next((f for f in protectedFiles if f in request_line),None):
                    reason.get("sus_file",lambda sf: "[-] Not Found")(fp_match)
                else: 
                    print(Fore.GREEN + f"[+] Normal request : {f_match}")




    def analyzeReq(self):
        methods = ['GET', 'POST', 'UPDATE', 'DELETE', 'PATCH']
        get_contents = re.search(r'"([^"]*)"', self.weblog)
        if not get_contents:
            print("[-] No quoted request found")
            return
        
        request_line = get_contents.group(0)
        self.table["content"].append(request_line)
        print(f"[+] Content : {get_contents.group(0)}")
        
        parts = request_line.split()
        
        method = parts[0].upper() if parts else ""
        
        
        status = re.search(r'\s+[1-5]\d{2}\s',self.weblog)
        self.table["status"].append(status.group())
        print(f"[+] Status code: {status.group()}")

        if method.replace('"','') not in methods:
            print(f"[-] Unknown method: {method}")
            return
        match method.replace('"',''):
            case "GET":
                self.getReqAnalyze(status,request_line)
                    

            case "POST":
                ap_match = [a for a in api_endpoints if a in request_line]
                if ap_match : 
                    print(Fore.GREEN + f"[+] Normal POST API : {ap_match[0]}")
                pf_match = [f for f in protectedFiles if f in request_line]
                if pf_match:
                    print(Fore.RED + f"[!] POST REQUEST ON PROTECTED FILE: {pf_match[0]}")
                e_match = [e for e in common_endpoints if e in request_line]
                if e_match:
                    if status.group().strip() in ["404","500","504"]:
                        print(Fore.YELLOW + f"[-] Server Error endpoint : {e_match[0]}")

            case _:
                print(f"[-] Unhandled method: {method}")

        url = re.search(r'https?://[a-z0-9]+\.[a-z]{2,}',self.weblog)
        if url: 
            print(f"[+] Referrer URL : {url.group()}")
            self.table['referrer_url'].append(url.group())
        else:
            print(f"[i] Referrer URL : -")
            self.table['referrer_url'].append('-')

        useragent = re.search(r'Mozilla/(?P<mozilla_ver>\d+\.\d+)\s*\((?P<os_info>[^)]+)\)\s*(?P<engine_and_browser>.*)',self.weblog)
        if useragent: 
            ua = f"{useragent.group('mozilla_ver')} {useragent.group('os_info')} {useragent.group('engine_and_browser').replace('"','')}" 
            print(f"[+] User Agent : {ua}")
            self.table['useragent'].append(ua)
        else: 
            print(f"[+] User Agent : None")
            self.table['useragent'].append("-")

    def ranking(self,rank):
        logRank = []
        logRank.append(self.weblog) 


    def returntable(self):
        print("-------------------------------")
        print("[+] Table")
        for i in range(len(self.table["ip"])): 
            print(f"[{i}] IP : {self.table['ip'][i]}, DATE : {self.table['date'][i]}, CONTENT : {self.table['content'][i]}, [{i}] STATUS CODE: {self.table['status'][i]}, [{i}] USER AGENT: {self.table['useragent'][i]}, [{i}] REFERRER URL: {self.table['referrer_url'][i]}")



class CLI:
    @staticmethod
    def parse_arguments():
        parser = argparse.ArgumentParser(description="LOG ANALYZER TOOL")
        parser.add_argument("-f","--file",type=str,required=False,help="File to scan (-u file or path to file)")
        return parser.parse_args()

    
if __name__ == "__main__":
    try: 
        init(autoreset=True)
        print("[i] Checking Web Logs") 
        cli = CLI()
        args = cli.parse_arguments()
        
        with open(args.file,'r') as file:
            for l in file:
                loganalyzer = LogAnalyzer(l,entry)    
                loganalyzer.analyzeLog()
                                
        # for l in norm :
        #     loganalyzer = LogAnalyzer(l,entry) 
        #     loganalyzer.analyzeLog()
        loganalyzer.returntable()
    except argparse.ArgumentError as ae:
        print(f"[!] {ae}")

    
    
    except Exception as e:
        print(f"[!] {e}")

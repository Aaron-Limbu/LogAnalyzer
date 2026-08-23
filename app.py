import re
from colorama import Fore, Back, Style, init    

#weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326'

#weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /.env HTTP/1.1" 200 2326'
table = {
    "ip":[],
    "date":[],
    "content":[],
    "status":[],
}
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
cserror = ['192.168.1.100 - - [22/Aug/2026:14:20:05 +0000] "GET /bad-link HTTP/1.1" 404 1245',
'172.217.16.142 - - [22/Aug/2026:15:32:41 +0000] "POST /checkout HTTP/1.1" 500 562',
'10.0.0.5 - - [22/Aug/2026:16:01:12 +0000] "GET /heavy-report HTTP/1.1" 504 0']


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

goodf_ext = [
    '.html',
    '.php',
    '.png',
    '.css',
]

class LogAnalyzer: 
    def __init__(self,weblog,table):
        self.weblog = weblog
        self.table = table

    def analyzeLog(self):
        ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
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

        


    def analyzeReq(self):
        methods = ['GET','POST','UPDATE','DELETE','PATCH']        
        get_contents = re.findall(r'"([^"]*)"',self.weblog)
        found_method = re.search(r'"[A-Za-z]{2}',self.weblog) 
        method = ""
        self.table["content"].append(get_contents)
        print(f"[+] Content : {get_contents}")
        for m in methods :
            if found_method.group()[1:3] == m[:2]:
                method = m

        if method == "GET":
            f_match = [n for n in badf_ext if badf_ext if n in get_contents[0]] 
            if f_match:
                print(Fore.YELLOW + f"[i] Suspicious request for FILE : {f_match[0]}")
            else: 
                f_match = [g for g in goodf_ext if goodf_ext if g in get_contents[0]]
                if f_match:
                    print(Fore.GREEN + f"[+] Normal request : {f_match[0]}")
            
            reqS = [s for s in status_codes if status_codes if s in self.weblog] #might have overcomplicated this#-_- idk
            """match reqS: 
                case ['200']:
                    print(Fore.RED + f"[!] Status code: {reqS[0]} for {f_match[0]} from IP: {self.table['ip']}")
                    self.table["status"].append(reqS)
                case ['403']:
                    print(Fore.YELLOW + f"[i] Status code: {reqS[0]} for {f_match[0]} (still suspicious) from IP: {self.table['ip']}")
                    self.table["status"].append(reqS)
                case _: 
                    print("[-] status not found")
                    self.table["status"].append("not found")
"""
    def returntable(self):
        print(f"[+] {self.table}")
        return self.table

if __name__ == "__main__":
    try: 
        init(autoreset=True)
        print("[i] Checking Web Logs") 
        for i,wlog in enumerate(norm) : 
            print(f"[+] id {i} : \'{wlog}\'")
            loganalyzer = LogAnalyzer(wlog,table)
            loganalyzer.analyzeLog()
            loganalyzer.returntable()
        #loganalyzer = LogAnalyzer(weblog,table)
        #loganalyzer.analyzeLog()
        #loganalyzer.returntable()
    except Exception as e:
        print(f"[!] {e}")

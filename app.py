import re
from colorama import Fore, Back, Style, init    

#weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326'

weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /.env HTTP/1.1" 200 2326'
table = {}

not_good = [
    '.env',
    'storage/laravel.log'
]

status_codes = [
    '200',"404","304","403","404","500"
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
            self.table["ip"] = ip
        date_pattern = r"\[\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\]"        
        found_date = []
        matched = re.search(date_pattern,self.weblog)
        found_date.append(matched.group())
        for date in found_date: 
            print(f"[+] date: {date}")
            self.table["date"] = date
        self.analyzeReq()

        


    def analyzeReq(self):
        methods = ['GET','POST','UPDATE','DELETE','PATCH']        
        get_contents = re.findall(r'"([^"]*)"',self.weblog)
        found_method = re.search(r'"[A-Za-z]{2}',self.weblog) 
        method = ""
        self.table["content"] = get_contents
        for m in methods :
            if found_method.group()[1:3] == m[:2]:
                method = m
        
        if method == "GET":
            match = [n for n in not_good if not_good if n in get_contents[0]] 
            if match:
                print(Fore.YELLOW + f"[i] Suspicious request for FILE : {match[0]}")
            reqS = [s for s in status_codes if status_codes if s in self.weblog] #might have overcomplicated this#-_- idk
            if (reqS[0] == '200'):
                print(Fore.RED + f"[!] Status code: {reqS[0]} for {match[0]} from IP: {self.table['ip']}")
            if (reqS[0] == '403'):
                print(Fore.YELLOW + f"[i] Status code: {reqS[0]} for {match[0]} (still suspicious) from IP: {self.table['ip']}")

    def returntable(self):
        print(f"[+] {self.table}")

if __name__ == "__main__":
    try: 
        init(autoreset=True)
        loganalyzer = LogAnalyzer(weblog,table)
        loganalyzer.analyzeLog()
        loganalyzer.returntable()
    except Exception as e:
        print(f"[!] {e}")

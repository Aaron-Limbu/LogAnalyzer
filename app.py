import re

weblog = '127.0.0.1 - - [20/Aug/2026:12:30:00 +0000] "GET /index.html HTTP/1.1" 200 2326'
table = {}

not_good = [
    '.env',
    'storage/laravel.log'
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
            
    def returntable(self):
        print(f"[+] {self.table}")

if __name__ == "__main__":
    try: 
        loganalyzer = LogAnalyzer(weblog,table)
        loganalyzer.analyzeLog()
        loganalyzer.returntable()
    except Exception as e:
        print(f"[!] {e}")

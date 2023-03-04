# SQLi-Hunter-v2
The second version of SQL Hunter. SQLi Hunter is a URL (Blind) SQL injection checker for multiple pages.

## What is SQLi Hunter v2?
SQLi Hunter v2 is a python program that checks for SQL (and Blind) injection vulnerability in URL's. The program is designed to be easy to use, practical and beneficial. The intention of this tool is to include it in your ethical Bug Bounty Hunting methodology. Please do not use this tool on any website without having its permission.

![2023-01-22 13_07_19-Window](https://user-images.githubusercontent.com/58238467/213914994-3656b239-5576-42d5-803d-f5a5c1350bc3.png)
> Checking for Blind SQL Injection in Kali Linux, with a hit received.

![rdp sqli hunter](https://user-images.githubusercontent.com/58238467/213915070-6bce1a9c-ca76-417b-aa89-91f3f90854aa.png)
> Checking for SQL injection in Windows.

## Some of SQLi Hunter v2 features
- Checks for SQL injection in multiple pages.
- Checks for Blind SQL injection in multiple pages.
- Checks multiple parameters in a single URL (if there's).
- The ability to receive vulnerable pages (Hits) on telegram.
- All the SQL injection detectors and errors are customizable in config folder.
- The ability to clean unwanted URL's before checking (URL's that doesn't include any parameters)
- Providing proxies while checking.
- Customizable user-agent and threads amount.

## Manual page in SQLi Hunter v2
```
C:\Users\a7\Desktop\SQLi Hunter v2>python "SQLi Hunter v2.py" -h
usage: SQLi Hunter v2.py [-h] [--blind] [--blind-timeout <int>] -url URL or FILE [--clean] [--proxy <FILE>]
                         [--proxy-type PROXY_TYPE] [-t <int>] [--timeout <int>] [--telegram] [--user-agent <str>] [-v]

options:
  -h, --help            show this help message and exit
  --blind               To tell the program that you want to test for blind SQL injection. Default detectors in
                        config/blind-SQLi-detectors.txt. You can change it if you want.
  --blind-timeout <int>
                        The blind sql detector timeout. ex. if the detector asks the website to wait 2 seconds, write
                        2 here. Default is 5 seconds
  -url URL or FILE      Could be a single URL or a file of URL's to check, ex (-url file.txt) or (-url
                        https://example.com/page.php?id=2
  --clean               Clean un-wanted URL's before checking.
  --proxy <FILE>        Use proxies file to check the URL's
  --proxy-type PROXY_TYPE
                        Proxies type (HTTP/S, SOCKS4 or SOCKS5)
  -t <int>              Amount threads. Default is 10
  --timeout <int>       The amount of milliseconds to wait until making a request to the next link (is it has the same
                        domain) to avoid false DoS attack against the domain. Default is 0 (one second is 1000)
  --telegram            To get hits on telegram, you can provide your bot's token and your telegram ID in this file
                        config/tele.txt in this format token/id
  --user-agent <str>    Specify certain user-agent. Default is random
  -v                    Increase verbosity
  ```
  
## Installing SQLi Hunter v2
1. On Linux distributions, you can use `git clone https://github.com/3a7/SQLi-Hunter-v2`
2. Install the requirements `pip install -r requirements.txt`
3. Give the executing right to SQLi Hunter v2.py file `chmod +x 'SQLi Hunter v2.py'`
3. Run the program! ex. `python 'SQLi Hunter v2.py' -url urls.txt --clean -v`


## The program is suitable for all different OS
Tested on 
- Linux distributions
- Windows 10 and 11
- Android (Termux App or any app that runs python files)
- IPhone (Pythonista).


## Note
- You can use different tools to get pages on a specific website. Tools like [GAU](https://github.com/lc/gau) and [hakrawler](https://github.com/hakluke/hakrawler) can help you with that.
- I will keep updating the prorgam in the future, so check the repository every now and then.
- If you're facing any issue while running the program, consider contacting me via telegram (@A7_acc) or Instagram (@a7.acc) and I'll help you fix it.
## Update v2.1 - 4 February 2023
- Double checking the Blind SQL injection pages.
- Simple patching.
## Update v2.2 - 3 March 2023
- More precis Blind SQL Injection hits (3 checks)
- `-d` Argument to decrease the amount of fake hits (for blind only)
## Happy Hacking :)

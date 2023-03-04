import argparse,sys,threading,schedule,requests
from config_file import *
from user_agent import generate_user_agent
from time import sleep
from random import choice
import urllib.parse

'''
This tool is made for finding SQL injection vulnerability in web pages. The intention of this tool is to include
it in your ethical Bug Bounty Hunting methodology. Please do not use this tool on any website 
without having its permission.

IG:       @a7.acc
GitHub:   @3a7
Linktree: https://linktr.ee/a7.acc


functions in order:
arguments()
telegram()
vulnerability()
run()
main()

Update v2.1 - 4 February 2023
- Double checking the Blind SQL injection pages.
- Simple patching

Update v2.2 - 3 March 2023
- More precis Blind SQL Injection hits (3 checks)
- -d Argument to decrease the amount of fake hits (for blind only)
'''

# Create an ArgumentParser object
parser = argparse.ArgumentParser()

# Add a command line argument
parser.add_argument('--blind',required=False, action='store_true', help='To tell the program that you want to test for blind SQL injection. Default detectors in config/blind-SQLi-detectors.txt. You can change it if you want.')
parser.add_argument('--blind-timeout',required=False, type=int, metavar='<int>', help='The blind sql detector timeout. ex. if the detector asks the website to wait 2 seconds, write 2 here. Default is 5 seconds')
parser.add_argument('-url' , required=True,type=file_or_url,metavar='URL or FILE',help='Could be a single URL or a file of URL\'s to check, ex (-url file.txt) or (-url https://example.com/page.php?id=2')
parser.add_argument('-d', action='store_true', help=f'Decrease the amount of hits to get 99 procent vulnerable pages ONLY')
parser.add_argument('--clean', action='store_true', help='Clean un-wanted URL\'s before checking.')
parser.add_argument('--proxy', type=argparse.FileType("r"),required=False,metavar='<FILE>', help='Use proxies file to check the URL\'s')
parser.add_argument('--proxy-type',required=False,type=proxy_types ,help='Proxies type (HTTP/S, SOCKS4 or SOCKS5)')
parser.add_argument('-t', type=int,required=False,metavar='<int>', help='Amount threads. Default is 10')
parser.add_argument('--timeout', type=int,required=False, metavar='<int>',help='The amount of milliseconds to wait until making a request to the next link (is it has the same domain) to avoid false DoS attack against the domain. Default is 0 (one second is 1000)')
parser.add_argument('--telegram', action='store_true', help='To get hits on telegram, you can provide your bot\'s token and your telegram ID in this file config/tele.txt in this format token/id')
parser.add_argument('--user-agent', type=str,required=False,metavar='<str>', help='Specify certain user-agent. Default is random')
parser.add_argument('-v', action='store_true', help='Increase verbosity')

# Parse the command line arguments
args = parser.parse_args()


# Dealing with arguments and setting them
def arguments():
    global detectors, urls, proxies, isproxy, threads, timeout, istelegram, telegram_info, agent, errors, blind_timeout, blind, verbose, decrease
    blind = False
    blind_timeout = 5
    urls = set()
    proxies = set()
    proxy_type = None
    clean = args.clean
    isproxy = False
    threads = 10
    timeout = 0
    istelegram = False
    telegram_info = None
    agent = generate_user_agent
    verbose = False
    decrease = args.d
    # Most Common SQL Injection Errors
    errors = [x for x in open('config/SQLi-errrors.txt','r',encoding='utf-8').read().splitlines()]

    

    # Retrieving the detectors / eihter blind or normal
    if args.blind:
        blind = True
        print(f'[{cyan(str(t()))}] Make sure you specified the correct timeout for Blind SQL Injection.')
        print(f'[{cyan(str(t()))}] If you are using the default Blind SQL Detectors you don\'t need to specifiy it')
        detectors = [x for x in open('config/blind-SQLi-detectors.txt','r',encoding='utf-8').read().splitlines()]
    else:
        detectors = [x for x in open('config/SQLi-detectors.txt','r',encoding='utf-8').read().splitlines()]

    if args.blind_timeout is not None:
        blind_timeout = args.blind_timeout
    
    # Checking -url argument
    if args.url[0] == 'FILE':
        # Here we are using .readlines() instead of .read().splitlines() to avoid MemoryError
        try:
            # file deepcode ignore PT: IGNORE
            with open(args.url[1],'r',encoding='utf-8') as file:
                for line in file.readlines():
                    urls.add(line.strip('\n'))
        except Exception as e:
            print('['+cyan(str(t()))+'] ',mark,yellow(str(e)))

    elif args.url[0] == 'URL':
        urls.add(args.url[1])

    # Checking --clean argument
    if clean:
        if args.url[0] == 'FILE':
            urls = clean_it(urls)

    # Checking proxies and proxies type (--proxy and --proxy-type)
    if args.proxy is not None:
        isproxy = True
        proxies_temp = [args.proxy.read().splitlines()]
        if args.proxy_type is None:
            msg = f'[{cyan(str(t()))}] You need to provide proxies type in order to use the proxy file. Please provide proxies type by using {cyan("--proxy-type")} [{cyan("HTTP HTTPS SOCKS4 SOCKS5")}]'
            raise NameError(msg)
        else:
            proxy_type = args.proxy_type
            for proxy in proxies_temp:
                if proxy_type == 'HTTP' or proxy_type == 'HTTPS':
                    proxies.add({
                        'http':f'https://{proxy}',
                        'https':f'http://{proxy}'
                    })
                elif proxy_type == 'SOCKS4':
                    proxies.add({
                        'http':f'socks4://{proxy}',
                        'https':f'socks4://{proxy}'
                    })
                elif proxy_type == 'SOCKS5':
                    proxies.add({
                        'http':f'socks5://{proxy}',
                        'https':f'socks5://{proxy}'
                    })
            proxies_temp.clear()

    # Checking --timeout
    if args.timeout is not None:
        timeout = args.timeout/1000

    # Checking threads -t
    if args.t is not None:
        threads = args.t

    # Checking --telegram
    if args.telegram:
        istelegram = True
        f = open('config/tele.txt','r',encoding='utf-8')
        telegram_info = f.read().strip('\n').split('/') #[token,id]
        f.close()

    # Checking --user-agent
    if args.user_agent is not None:
        agent = lambda : args.user_agent

    if args.v is not None:
        if args.v:
            verbose = True
    urls = list(urls)


# Sends information to telegram. info -> string (url encoded)
def telegram(info):
    if istelegram:
        try:
            requests.post(f'https://api.telegram.org/bot{telegram_info[0]}/sendMessage?chat_id={telegram_info[1]}&text={info}')
        except Exception as ex:
            print('['+cyan(str(t()))+'] ',mark,'Error while sending info via telegram: ',yellow(str(ex)))


# To keep track of everything
bad = 0      # Un-vulnerable pages // requests that sent 
hits = 0     # Vulnerable pages
error = 0    # Errored requests (timed-out, no response)
checked = 0  # Checked urls

# The core function that checks every URL
def vulnerability():
    global checked, bad, hits, error, urls, proxies

    # While loop for every url
    while checked < len(urls):
        site = urls[checked]
        checked += 1

        # 1. Printing the information
        if ops == 'Windows':
            system(f'title ALL:{str(checked)}/{str(len(urls))}   HIT:{str(hits)}   BAD:{str(bad)}   ERROR:{str(error)}   THREADS:{str(threading.active_count()-1)}')
        else:
            sys.stdout.flush()
            print(f"\r{cyan('ALL')}:{str(checked)}/{str(len(urls))}   {green('HIT')}:{str(hits)}   {red('BAD')}:{str(bad)}   {yellow('ERROR')}:{str(error)}   {blue('THREADS')}:{str(threading.active_count()-1)}",end=' ')
        

        if site.count('=') > 1 and '&' in site:  # This means we have multiple parameters to check
            params = site.split('?')[1].split('&')
        else:
            params = [site]

        
        # Loop through parameters
        for param in params:
            done = False
            after_param = site.index(param)+len(param) # the index of after the parameter. ex. id=3<here>
            urli = site[0:after_param]                  # Website including the param

            # Loop through all detectors
            for symbol in detectors:
                url = urli+symbol+site[after_param:] # adding the symbol and completing the url
                curl = urli+blue(symbol)+site[after_param:]
                blind_error = False

                try:
                    if checked != 0 and timeout > 0:
                        if urls[checked-1].split('/')[2] == site.split('/')[2]: # if the current url and previuos url have the same domain
                            sleep(timeout)

                    if 'http' in param and '://' in param:
                        param = param.split('?')[-1]
                        
                    if verbose:
                        print(f"[{cyan(str(param))}] [{blue(symbol)}] Checking: ",curl)

                    if blind:
                        try: # Blind check no 1
                            if isproxy:
                                res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout)-1,proxies=choice(proxies))
                            else:
                                res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout)-1)
                        except requests.exceptions.ReadTimeout:
                            blind_error = True
                    else:
                        if isproxy:
                            res = requests.get(str(url),headers={'user-agent':agent()},timeout=10,proxies=choice(proxies))
                        else:
                            res = requests.get(str(url),headers={'user-agent':agent()},timeout=10)
                except:
                    error += 1
                    continue
                
                response = res.text

                # If we're checking for blind sql injection
                if blind:
                    if blind_error: 
                        try: # blind check no 2
                            if isproxy:
                                res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout+5),proxies=choice(proxies))
                            else:
                                res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout+5))
                            
                            # Here it means the page is 99% vulnerable to Blind
                            # blind check no 3

                            # In the payload we're replacing the current timeout with a higher one and checking if 
                            # it's only the website that is taking time to load or it's actually vulnerable
                            url = urli+symbol.replace(str(blind_timeout),str(blind_timeout+10))+site[after_param:]

                            try:
                                if isproxy:
                                    res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout+5),proxies=choice(proxies))
                                else:
                                    res = requests.get(str(url),headers={'user-agent':agent()},timeout=int(blind_timeout+5))
                            
                            except requests.exceptions.ReadTimeout:        # the page is 99% vulnerable to Blind
                                hits += 1
                                inf = hit(url,requests.exceptions.ReadTimeout,symbol,param,True)
                                telegram(urllib.parse.quote(inf))
                                done = True
                                break
                                
                        except requests.exceptions.ReadTimeout:        # the page is 50% vulnerable to Blind
                            if not decrease:
                                hits += 1
                                inf = hit(url,requests.exceptions.ReadTimeout,symbol,param,False)
                                telegram(urllib.parse.quote(inf))
                            else:
                                bad += 1
                            done = True
                            break
                    else:
                        bad += 1
                        continue

                else:
                    # loops through errors to check them
                    for er in errors:
                        if er in response:
                            # Checks again because sometimes the page includes that string inside it without being vulnerable
                            try:
                                if isproxy:
                                    res2 = requests.get(str(site),headers={'user-agent':agent()},timeout=10,proxies=choice(proxies))
                                else:
                                    res2 = requests.get(str(site),headers={'user-agent':agent()},timeout=10)
                                if er in res2.text: # page includes the error without being vulnerable
                                    continue
                                else:               # the page is 99% vulnerable
                                    hits += 1
                                    inf = hit(url,er,symbol,param,True)
                                    telegram(urllib.parse.quote(inf))
                                    done = True
                                    break
                            except:
                                pass
                            # the page is 50% vulnerable
                            hits += 1
                            inf = hit(url,er,symbol,param,False)
                            telegram(urllib.parse.quote(inf))
                            done = True
                            
                            break
                    else:
                        bad += 1
                if done:
                    break

        # 2. Printing the information
        if ops == 'Windows':
            system(f'title ALL:{str(checked)}/{str(len(urls))}   HIT:{str(hits)}   BAD:{str(bad)}   ERROR:{str(error)}   THREADS:{str(threading.active_count()-1)}')
        else:
            sys.stdout.flush()
            print(f"\r{cyan('ALL')}:{str(checked)}/{str(len(urls))}   {green('HIT')}:{str(hits)}   {red('BAD')}:{str(bad)}   {yellow('ERROR')}:{str(error)}   {blue('THREADS')}:{str(threading.active_count()-1)}",end=' ')

# Dealing with threads and starting them
def run():
    global running

    # Checks every second if the program is finished or not by checking if the active threads are only 1
    def CheckThreads():
        global running
        if threading.active_count() == 1:
            running = False

    # Starting the threads
    for _ in range(threads):
        thread1 = threading.Thread(target=vulnerability)
        thread1.start()

    # Running CheckThreads() function every second
    schedule.every().second.do(CheckThreads)

    # Checking the running variable if it's True or False
    while running:
        schedule.run_pending()
        sleep(1)
    else:  # means the program is stopped
        thread1.join()
        return



# The main function
def main():
    global running
    running = True

    try:

        # Brings all arguments
        arguments()

        # Starting the program (Only returns if the program stopped)
        run()

        # Status
        print('['+cyan(str(t()))+'] ', hashtag, 'Done checking all url\'s!',hashtag)
        print(mult,f"{cyan('ALL')}: {str(checked)}/{str(len(urls))}")
        print(mult,f"{green('HIT')}: {str(hits)}")
        print(mult,f"{red('BAD')}: {str(bad)}")
        print(mult,f"{yellow('ERROR')}: {str(error)}")
    except KeyboardInterrupt:
        running = False
        print('Bye :)\nTerminating all threads..')
        sys.exit()


if __name__ == '__main__':
    main()

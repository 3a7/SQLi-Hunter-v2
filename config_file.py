import platform,datetime
from colored import fg,attr
from os import system
from time import sleep

'''
This file must be included in the same folder as SQLi Hunter v2.
'''

# Detecting the OS
ops_release = str(platform.release())
ops = str(platform.system())
if '2012ServerR2' not in ops_release and ops == 'Windows' or ops == 'Linux':
    green = lambda x : fg('green')+x+attr('reset')
    red = lambda x : fg('red')+x+attr('reset')
    blue = lambda x : fg('blue')+x+attr('reset')
    yellow = lambda x : fg('yellow')+x+attr('reset')
    cyan = lambda x : fg('cyan')+x+attr('reset')
    magenta = lambda x : fg('magenta')+x+attr('reset')
    clear = lambda: system("cls")
    if ops == 'Linux':
        clear = lambda: system("clear")
else:
    green = lambda x : x
    red = lambda x : x
    blue = lambda x : x
    yellow = lambda x : x
    cyan = lambda x : x
    magenta = lambda x : x
    clear = lambda: system("cls")


# Markers
t = lambda : str(datetime.datetime.now())
mark = '['+red('!')+']'
question = '['+magenta('?')+']'
hashtag  ='['+green('#')+']'
mult = '['+blue('*')+']'
time = '['+cyan(str(t()))+'] '


'''
FUNCTIONS TO CHECK THE GIVEN ARGUMENTS
'''

# Define a custom type for a list of integers separated by a comma
def comma_separated_strings(string):
    return [x for x in string.split(',')]


# Checks whether the given argument is a url or file
def file_or_url(string):
    global url_detectors
    url_detectors = ['http','://','?','.','/','=']
    if len(string.split('.')) == 2 and '.txt' in string:
        return 'FILE',string
    else:
        if [d for d in url_detectors if d in string] == url_detectors:
            return 'URL',string
        else:
            msg = f"'{red(string)}' is invalid url or file. Example of a url: {green('https://example.com/page.php?key=value')}. Example of a file: {green('url_file.txt')}\n URL must include {yellow(str(' '.join(url_detectors)))} and file must be .txt file"
            raise SyntaxError(msg)

def proxy_types(string):
    p_types = 'HTTP HTTPS SOCKS4 SOCKS5'
    if string.upper() in p_types:
        return string.upper()
    else:
        msg = f"'{string.upper()}' is invalid proxy type. Available proxy types are: {p_types}"
        raise SyntaxError(msg)



# Cleaning function
def clean_it(url_file):

    stage1 = set()
    before = len(url_file)

    print(time, mult, 'Cleaning the file, this process may take few minutes, please be patient...')
    for url in url_file:
        if ([d for d in url_detectors if d in url] == url_detectors) and (not url.endswith('/')):
            stage1.add(url)
    print(time, mult, 'Cleaning is done.')

    with open('clean.txt','w',encoding='utf-8') as cl:
        for u in stage1:
            cl.write(u+'\n')

    print(time,hashtag, 'Clean URL\'s saved in',cyan('clean.txt'))
    print(time,hashtag, 'Befor cleaning:',blue(str(before)),'After cleaning:',green(str(len(stage1))))
    sleep(2)
    return stage1


def hit(site,error,symbol,param,possibility):
    if possibility:
        possibility = '90% Possibility'
    else:
        possibility = '50% Possibility'

    information = f"\n===========================\n{hashtag} PAGE: {green(str(site))}\n{hashtag} VULNERABLE PARAMETER: {blue(param)}\n{hashtag} SYMBOL: {cyan(symbol)}\n{hashtag} ERROR: {yellow(str(error))}\n{hashtag} VULNERABLE: {red(str(possibility))}\n{hashtag} DATE: {str(datetime.datetime.now())}\n===========================\n"
    info_raw = f"===========================\n[#] PAGE: {str(site)}\n[#] VULNERABLE PARAMETER: {str(param)}\n[#] SYMBOL: {str(symbol)}\n[#] ERROR: {str(error)}\n[#] VULNERABLE: {str(possibility)}\n[#] DATE: {str(datetime.datetime.now())}\n[#] Program By: @A7_acc\n===========================\n"
    
    print(information)

    try:
        file = open('vulnerable_sites.txt','a', encoding='utf-8')
    except:
        file = open('vulnerable_sites.txt','w', encoding='utf-8')
    
    file.write(info_raw)
    file.close()
    
    return info_raw
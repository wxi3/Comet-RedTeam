import asyncio
import concurrent
from concurrent.futures import ThreadPoolExecutor
import config
import httpx
import json
import re
import pymongo
import requests
import random
import threading
from bs4 import BeautifulSoup
from tools.nuclei_scan import nuclei_scan
from tools.afrog_Scan import afrog_scan


header = random.choice(config.headers)
header = {'user-agent':header}

with open("static\\finger.json", "r", encoding='utf-8') as f:
    fingerprints = json.load(f)

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["testsubdomain"]

domains = set()
alive_domains = set()


def get_fileleak(domains):
    fileleakInfo = db["fileleakInfo"]
    collection = db["domainInfo"]
    sensitive_files = []
    with open('static/file_dict.txt', 'r') as f:
        sensitive_files = [line.strip() for line in f.readlines()]
    query = {"subdomain": next(iter(domains))}
    projection = {"task_name": 1, "_id": 0}
    result = collection.find_one(query, projection)
    taskname = result["task_name"]
    def check_file(domain, sensitive_file):
        url = f'https://{domain}/{sensitive_file}'
        url_raw = f'https://{domain}'
        response = httpx.get(url=url, headers=header, timeout=5)
        response_raw = httpx.get(url=url_raw, headers=header, timeout=5)
        try:
            status_code = response.status_code
            content_length = len(response.content)
            content_length_raw = len(response_raw.content)
            title = get_title(response)
            title_raw = get_title(response_raw)
            # & content_length != content_length_raw & title_raw != title
            if status_code == 200:
                print(f'URL: {url} , title: {title} , size:{content_length} ')
                document = {
                    'task_Name': taskname,
                    'url': url,
                    'title': title,
                    'size': content_length,
                }
                fileleakInfo.insert_one(document)
        except httpx.RequestError as e:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        for domain in domains:
            for sensitive_file in sensitive_files:
                executor.submit(check_file, domain, sensitive_file)
    print('-------------------------敏感文件检测完成---------------------------------')


def get_title(response):
    # Extract the title from the response HTML, if available
    if 'text/html' in response.headers.get('Content-Type', ''):
        try:
            title = response.content.split(b'<title>')[1].split(b'</title>')[0].decode('utf-8', errors='ignore')
            # return response.text.split('<title>', 1)[1].split('</title>', 1)[0].strip()
            return title
        except IndexError:
            pass
    return None

def identify_cms(url):

    try:

        # 发送HTTP请求获取网页源代码，并根据指纹匹配规则来识别CMS信息
        response = requests.get(url=url, timeout=10, verify=False)
        html = response.text

        for finger in fingerprints['fingerprint']:
            if finger["location"] == "body":
                if finger["method"] == "keyword":
                    for keyword in finger["keyword"]:
                        if keyword in html:
                            return finger['cms']
                            break
                elif finger["method"] == "faviconhash":
                    # 从HTML源代码中获取网站favicon的URL，并下载该文件并计算哈希值
                    # 如果哈希值与指纹匹配，则说明网站使用该CMS
                    # 下载网站的favicon
                    favicon_url = url + '/favicon.ico'
                    favicon = httpx.get(favicon_url, verify=False)

                    if favicon.status_code == 200:
                        # 计算哈希值
                        md5 = hashlib.md5()
                        md5.update(favicon.content)
                        hash_value = md5.hexdigest()

                        if hash_value == finger["keyword"][0]:
                            return finger['cms']
                            break
                elif finger["method"] == "GET":
                    path = finger["path"]
                    path_url = url + path
                    path_html = requests.get(path_url,verify=False)
                    for keyword in finger["keyword"]:
                        if keyword in path_html.text:
                            return finger["cms"]
                            break

            elif finger["location"] == "header":
                for keyword in finger["keyword"][0]:
                    if keyword.lower() in response.headers:
                        return finger['cms']
                        break
            else:
                return 'unknow'
    except Exception as e:
        return 'unknown'

def check_subdomains(domains, taskname,sensitive_scan,enable_nuclei,enable_afrog):
    collection = db["domainInfo"]
    with ThreadPoolExecutor(max_workers=200) as executor:
        for domain in domains:
            for port in config.Web_port:
                executor.submit(scan, domain, port, taskname, collection)
    print('-----------------------------存活检测完成--------------------------------------')
    if sensitive_scan:
        print("---------------------------------开始敏感文件扫描------------------------------")
        get_fileleak(alive_domains)
    elif enable_afrog:
        print("---------------------------------开始afrog漏洞扫描---------------------------")
        afrog_result = afrog_scan(alive_domains,taskname)
        print(afrog_result)
        print("---------------------------------afrog漏洞扫描结束---------------------------")
    elif enable_nuclei:
        print("---------------------------------开始nuclei漏洞扫描---------------------------")
        results = nuclei_scan(alive_domains)
        print(results)
        print("---------------------------------nuclei漏洞扫描结束---------------------------")
    else:
        print('----------------------不进行敏感文件扫描------------------------------------')

def scan(domain, port, taskname, collection):
    try:
        url = f'http://{domain}:{port}'
        response = requests.get(url=url, timeout=3, headers=header)
        if response.status_code in [200, 301, 403, 404]:
            cms = identify_cms(url)
            document = {
                'task_name': taskname,
                'subdomain': domain,
                'status_code': response.status_code,
                'title': get_title(response),
                'cms': cms,
            }
            alive_domains.add(domain)
            collection.insert_one(document)
    except requests.exceptions.RequestException:
        pass

def get_domains(domain, pages,taskname,sensitive_scan,enable_nuclei,enable_afrog):

    page = 1

    while page <= pages:
        url = 'https://rapiddns.io/s/' + str(domain) + '?page=' + str(page) + '#result'
        res = httpx.get(url=url, headers=header, timeout=(10, 10), verify=False)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            table = soup.find('table', {'id': 'table'})
            tbody = table.find('tbody')
            tds = tbody.find_all('td')

            for td in tds:
                if td.find('a') is None:
                    if domain in td.text:
                        domains.add(td.text)
            page += 1
        else:
            print(f"Rapiddns 请求失败，状态码：{res.status_code}")
    get_domainsByVirusTotal(domain)
    print('-------------------------------域名收集完成-----------------------------------------------')
    check_subdomains(domains,taskname,sensitive_scan,enable_nuclei,enable_afrog)

def get_pages(domain):
    url = 'https://rapiddns.io/s/' + domain + '#result'
    res = httpx.get(url=url, headers=header, timeout=(10, 10), verify=True)
    regx = r'<span style="color: #39cfca; ">(.*?)</span>'
    count_array = re.findall(regx, res.text)
    count = count_array[0]
    pages = int(count) / 100
    if pages > int(pages):
        real_page = pages + 1
    else:
        real_page = pages

    return int(real_page)

def get_domainsByVirusTotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
    headers = {
        "accept": "application/json",
        "x-apikey": config.VirusTotal_key
    }
    response = requests.get(url=url, headers=headers,timeout=10,verify=False)
    if response.status_code == 200:
        json_data = json.loads(response.text)

        for data in json_data["data"]:
            id_value = data["id"]
            domains.add(id_value)
    else:
        print(f"VirusTotal请求失败，状态码：{response.status_code}")
        pass


def verify_waf(headers, content):
    for i in config.WAF_RULE:
        name, method, position, regex = i.split('|')
        if method == 'headers':
            if headers.get(position) is not None:
                if re.search(regex, str(headers.get(position))) is not None:
                    return True
        else:
            if re.search(regex, str(content)):
                return True

    return False


def check_waf(url):
    result = False
    try:
        r = requests.get(url=url,headers=header,timeout=5,verify=False)
        result = verify_waf(r.headers, r.text)
        if result != False:
            for i in config.payload:
                url_evil = url + i
                r = requests.get(url=url_evil,headers=header,timeout=5,verify=False)
                result = verify_waf(r.headers, r.text)

                return result
        else:

            return result
    except (UnboundLocalError, AttributeError):
        pass
    except Exception as e:
        pass
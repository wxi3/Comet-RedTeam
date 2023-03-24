import json
import random
import datetime
from subprocess import check_output
import re
import pymongo
import requests
from flask import Flask
from flask import request,session,redirect,url_for,jsonify
from flask import render_template
from flask_pymongo import PyMongo
from flask_paginate import Pagination, get_page_parameter
from pymongo import collection
from bs4 import BeautifulSoup
import urllib3
import hashlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'fucksafe'


# 创建MongoDB客户端
client = pymongo.MongoClient("mongodb://localhost:27017/")
    # 选择数据库和集合
db = client["testsubdomain"]

headers=['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36','Mozilla/5.0 (Windows; U; Windows NT 5.1) Gecko/20070803 Firefox/1.5.0.12','Mozilla/5.0 (Macintosh; PPC Mac OS X; U; en) Opera 8.0','Mozilla/5.0 (iPhone; U; CPU like Mac OS X) AppleWebKit/420.1 (KHTML, like Gecko) Version/3.0 Mobile/4A93 Safari/419.3','Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.12) Gecko/20080219 Firefox/2.0.0.12 Navigator/9.0.0.6','Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; 360SE)','Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0;Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; Maxthon/3.0)','Mozilla/5.0 (Windows NT 5.1) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.5 Safari/534.55.3','Mozilla/5.0 (Linux; U; Android 4.0.3; zh-cn; M032 Build/IML74K) AppleWebKit/533.1 (KHTML, like Gecko)Version/4.0 MQQBrowser/4.1 Mobile Safari/533.1','Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3']
header = random.choice(headers)
header = {'user-agent':header}
domains = set()

with open("static\\finger.json", "r", encoding='utf-8') as f:
    fingerprints = json.load(f)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/welcome')
def welcome():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        return render_template('welcome.html')
    else:
        return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/test'
    mongo = PyMongo(app)
    user = mongo.db.user.find_one({'username': username})

    if user:
        if user['password'] == password:
            session['user'] = username
            return render_template('welcome.html')
            # return redirect(url_for('/admin'))
        else:
            return jsonify({'success': False, 'message': '用户名或密码错误'})
    else:
        return jsonify({'success': False, 'message': '用户名不存在'})

    return render_template('login.html')

@app.route('/logout',methods=['GET','POST'])
def logout():
    session.pop('user', None)
    return render_template('login.html')


@app.route('/create_task', methods=['GET','POST'])
def create_task():
    if request.method == 'POST':
        collection = db["taskInfo"]
        task_Name = request.form['task_name']
        task_Targets = request.form['targets']
        task_Time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        task_info = {
            "task_Name": task_Name,
            "task_Targets": task_Targets,
            "task_Time": task_Time
        }
        collection.insert_one(task_info)
        pages = get_pages(task_Targets)
        get_domains(task_Targets,pages)

    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        return render_template('create_task.html')
    else:
        return render_template('login.html')

@app.route('/tasklist', methods=['GET'])
def tasklist():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        collection = db["taskInfo"]
        count = collection.count_documents({})
        if count > 0:
            for x in collection.find():
                task_Name = x['task_Name']
                task_Targets = x['task_Targets']
                task_Time = x['task_Time']
            return render_template('tasklist.html',task_Name=task_Name,task_Targets=task_Targets,task_Time=task_Time)
        else:
            return render_template('tasklist.html')
    else:
        return render_template('login.html')


@app.route('/vulninfo', methods=['GET','POST'])
def vulninfo():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        return render_template('vulninfo.html')
    else:
        return render_template('login.html')

@app.route('/subdomainInfo', methods=['GET','POST'])
def subdomainInfo():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        return render_template('subdomain_info.html')

    else:
        return render_template('login.html')

@app.route('/get_sub_page', methods=['POST'])
def get_data():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        collection = db["domainInfo"]
        result = collection.find()
        data = []
        for document in result:
            subdomain = document.get("subdomain")
            status_code = document.get("status_code")
            title = document.get("title")
            cms = document.get("cms")
            data.append({"subdomain": subdomain, "status_code": status_code, "title": title, "cms": cms})

        limit = int(request.form.get("pageSize"))
        page = int(request.form.get("currentPage"))

        start = (page - 1) * limit
        end = start + limit
        ret = [{"id": i, "name": d["subdomain"], "status": d["status_code"], "title": d["title"], "cms": d["cms"]} for i, d in
               enumerate(data[start:end], start=start)]
        return {"data": ret, "count": len(data)}

@app.route('/sysconfig', methods=['GET','POST'])
def sysconfig():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        if request.method == 'POST':
            email = request.form['email']
            key = request.form['key']
            print(email)
            print(key)
        return render_template('sysconfig.html')
    else:
        return render_template('login.html')


def get_pages(domain):
    url = 'https://rapiddns.io/s/' + domain + '#result'
    res = requests.get(url=url, headers=header, timeout=(10, 10), verify=True)
    regx = r'<span style="color: #39cfca; ">(.*?)</span>'
    count_array = re.findall(regx, res.text)
    count = count_array[0]
    pages = int(count) / 100
    if pages > int(pages):
        real_page = pages + 1
    else:
        real_page = pages

    return int(real_page)


def get_domains(domain, pages):

    page = 1

    while page <= pages:
        url = 'https://rapiddns.io/s/' + str(domain) + '?page=' + str(page) + '#result'
        res = requests.get(url=url, headers=header, timeout=(10, 10), verify=False)
        soup = BeautifulSoup(res.text, 'html.parser')
        table = soup.find('table', {'id': 'table'})
        tbody = table.find('tbody')
        tds = tbody.find_all('td')

        for td in tds:
            if td.find('a') is None:
                if domain in td.text:
                    domains.add(td.text)
        page += 1
    check_subdomains(domains)

def check_subdomains(domains):

    collection = db["domainInfo"]
    for domain in domains:
        try:
            url = 'https://' + domain
            response = requests.get(f'https://{domain}', timeout=3)
            if response.status_code in [200, 301, 403]:
                cms = identify_cms(url)
                document = {
                    'subdomain': domain,
                    'status_code': response.status_code,
                    'title': get_title(response),
                    'cms': cms,
                }
                collection.insert_one(document)
        except requests.exceptions.RequestException:
            pass

def get_title(response):
    # Extract the title from the response HTML, if available
    if 'text/html' in response.headers.get('Content-Type', ''):
        try:
            return response.text.split('<title>', 1)[1].split('</title>', 1)[0].strip()
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
                    favicon = requests.get(favicon_url, verify=False)

                    if favicon.status_code == 200:
                        # 计算哈希值

                        md5 = hashlib.md5()
                        md5.update(favicon.content)
                        hash_value = md5.hexdigest()

                        if hash_value == finger["keyword"][0]:
                            return finger['cms']
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

if __name__ == '__main__':
    app.run(debug=True)

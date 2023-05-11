import datetime
import config
import functions
from flask import Flask
from flask import request,session,redirect,url_for,jsonify
from flask import render_template
from flask_pymongo import PyMongo
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = 'fucksafe'


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
        collection = functions.db["taskInfo"]
        task_Name = request.form['task_name']
        task_Targets = request.form['targets']
        task_Time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        sensitive_scan = request.form.get('sensitive_files_scan')  # 获取敏感文件扫描的选中状态
        enable_nuclei = request.form.get('enable_nuclei')
        enable_subDomain = request.form.get('enable_subDomain')
        enable_afrog = request.form.get('enable_afrog')
        targets_list = task_Targets.split()
        print(f"是否进行敏感文件扫描：{sensitive_scan}")
        print(f"是否启用Nuclei：{enable_nuclei}")
        print(f"是否启用afrog：{enable_afrog}")
        print(f"是否启用子域名爆破：{enable_subDomain}")
        task_info = {
            "task_Name": task_Name,
            "task_Targets": task_Targets,
            "task_Time": task_Time,
            "sensitive_scan": sensitive_scan,  # 将敏感文件扫描的选中状态存储到 task_info 中
            "enable_nuclei": enable_nuclei,  # 将启用 Nuclei 的选中状态存储到 task_info 中
            "enable_subDomain":enable_subDomain,
            "enable_afrog":enable_afrog
        }
        collection.insert_one(task_info)
        pages = functions.get_pages(task_Targets)
        if enable_subDomain:
            functions.get_domains(task_Targets, pages, task_Name,sensitive_scan,enable_nuclei,enable_afrog)
        else:
            functions.check_subdomains(targets_list,task_Name,sensitive_scan,enable_nuclei,enable_afrog)

    if 'user' in session:
        username = session['user']
        return render_template('create_task.html')
    else:
        return render_template('login.html')


@app.route('/tasklist', methods=['GET'])
def tasklist():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        collection = functions.db["taskInfo"]
        count = collection.count_documents({})
        tasks = []
        if count > 0:
            for x in collection.find():
                task_Name = x['task_Name']
                task_Targets = x['task_Targets']
                task_Time = x['task_Time']
                task_child = {'task_Name': task_Name, 'task_Targets': task_Targets, 'task_Time': task_Time}
                tasks.append(task_child)
            return render_template('tasklist.html',tasks=tasks)
        else:
            return render_template('tasklist.html')
    else:
        return render_template('login.html')


@app.route('/vulninfo', methods=['GET', 'POST'])
def vulninfo():
    if 'user' in session:
        username = session['user']
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        results = []
        count = functions.db.VulnInfo.count_documents({})
        vulninfos = functions.db.VulnInfo.find().skip((page - 1) * per_page).limit(per_page)
        for vulninfo in vulninfos:
            result = {
                'vuln_name': vulninfo['vuln_name'],
                'vuln_severity': vulninfo['vuln_severity'],
                'vuln_url': vulninfo['vuln_url'],
            }
            results.append(result)
        return render_template('vulninfo.html', results=results, page=page, per_page=per_page, count=count)
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
        collection = functions.db["domainInfo"]
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
        return render_template('sysconfig.html',Fofa_email=config.Fofa_email,Fofa_key=config.Fofa_key,VirusTotal_key=config.VirusTotal_key)
    else:
        return render_template('login.html')

@app.route('/del_task', methods=['POST'])
def del_task():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        task_name = request.form.get('task_name')
        collection_subdomains = functions.db['domainInfo']
        collection_task = functions.db['taskInfo']
        collection_fileleakInfo = functions.db['fileleakInfo']

        collection_subdomains.delete_many({'task_name': task_name})
        collection_task.delete_many({'task_Name': task_name})
        collection_fileleakInfo.delete_many({'task_Name': task_name})
        return redirect(url_for('tasklist'))
    else:
        return render_template('login.html')


@app.route('/fileleak', methods=['GET','POST'])
def fileleak():
    if 'user' in session:  # 修改这里的判断条件
        username = session['user']
        #
        #
        #
        # limit = int(request.form.get("pageSize"))
        # page = int(request.form.get("currentPage"))
        #
        #
        #
        # ret = [{"id": i, "name": d["subdomain"], "status": d["status_code"], "title": d["title"], "cms": d["cms"]} for
        #        i, d in
        #        enumerate(data[start:end], start=start)]
        # return {"data": ret, "count": len(data)}
        return render_template('fileleak.html')

    else:
        return render_template('login.html')

@app.route('/leakfile_data')
def get_leakfile_data():
    collection = functions.db["fileleakInfo"]
    page = int(request.args.get('page'))
    limit = int(request.args.get('limit'))
    skip = (page - 1) * limit
    result = collection.find({}, {"_id": 0, "url": 1, "title": 1, "size": 1}).skip(skip).limit(limit)
    data = []
    for document in result:
        url = document.get("url")
        title = document.get("title")
        size = document.get("size")
        data.append({"url": url, "title": title, "size": size})
    total = collection.count_documents({})
    return jsonify({"code": 0, "msg": "", "count": total, "data": data})


if __name__ == '__main__':
    app.run(debug=True)

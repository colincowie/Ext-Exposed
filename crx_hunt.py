import csv, re, os
import hashlib
import argparse
import requests
import logging
import uuid
import types
import json
import redis, time
from rq import Queue
from flask_wtf import FlaskForm
from elasticsearch import Elasticsearch
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, flash, redirect, render_template, request, session ,url_for, send_from_directory
from selenium import webdriver


# import my python scripts for extensions
from ext_sandbox import EXT_Sandbox, sandbox_run
from ext_analyze import EXT_Analyze, static_run

app = Flask(__name__)
es = Elasticsearch()
r = redis.Redis()
q = Queue(connection=r)
logger = logging.getLogger("testing")
logger.info("test with a new log")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crxhunt.db'
db = SQLAlchemy(app)
Base = declarative_base()
Base.query = db.session.query_property()

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Submit')

class User(db.Model):
    """ Create user table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String())

    def __init__(self, username, password):
        self.username = username
        self.password = password

@app.route('/hunt')
def hunt():
    """ Session control"""
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        # Check ES Status
        es = Elasticsearch(['http://localhost:9200/'])
        if not es.ping():
            es_status = False
        else:
            es_status = True
        return render_template("hunt.html",es_status=es_status)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Form"""
    if request.method == 'GET':
        return render_template('login.html')

    else:
        name = request.form['username']
        password = hashlib.sha256(request.form["password"].encode("utf-8")).hexdigest()
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.password == password:
            # Todo: Research how to improve access tokens
            session['logged_in'] = True
            flash('Welcome to Ext Exposed, '+str(name)+'!')

            return redirect(url_for('home'))
        else:
            return render_template('login.html',message='Invalid Login')

@app.route('/nobotsplz/register/', methods=['GET', 'POST'])
def register():
    """Register Form"""
    if request.method == 'POST':
        # Create new user with sha256 hashed password
        new_user = User(
            username=request.form['username'],
            password=hashlib.sha256(request.form["password"].encode("utf-8")).hexdigest()
            )
        user = User.query.filter_by(username=request.form["username"]).first()
        if user:
            return 'That username is taken.'
        else:
            db.session.add(new_user)
            db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/logout")
def logout():
    """Logout Form"""
    session['logged_in'] = False
    return redirect(url_for('home'))

@app.route('/scan', methods=['POST'])
def scan():
    if not session.get('logged_in'):
        return render_template('login.html')
    elif not es:
        return "Elasticsearch database error"
    else:
        if not es.ping():
            flash('Error: The elasticsearch database is not connected.')
            return redirect(url_for('home'))
        else:
            es_status = True
        # Get search query
        keyword = request.form['keyword']
        # get ext id
        ext_id = re.findall('[a-z]{32}',keyword)     # Parse the extension id from url
        ext_id = str(ext_id[0])
        new_jobs = {
            'static':'',
            'dynamic':''
        }
        try:
            jobs = q.jobs
        except:
            return "Critial Error: redis server not working, sandbox not ran. Please run `redis-server` and `rq worker`"


        if request.form.get("static") != None:
            # Static Analysis
            print("[!] Queuing static analysis for "+ext_id)

            ext_scan = EXT_Analyze(ext_id)
            ext_name = ext_scan.name
            print("name: "+ext_name)
            static_job = q.enqueue(static_run, ext_scan, ext_id, ext_name)
            time.sleep(2)
            #print(job.result)
            print("[!] Static enqueued at "+str(static_job.enqueued_at)+" with job id: "+str(static_job.id))
            new_jobs['static'] = str(static_job.id)

        if request.form.get("sandbox") != None:
            print("[!] Queuing sandbox for "+ext_id)
            # Sandbox
            time_limit = int(request.form.get('time_limit'))
            print("Time limit:"+str(time_limit))

            id = uuid.uuid4()
            box = EXT_Sandbox(ext_id, time_limit)
            sandbox_job = q.enqueue(sandbox_run, box, id)
            time.sleep(2)
            #print(job.result)
            print("[!] Dynamic enqueued at "+str(sandbox_job.enqueued_at)+" with job id: "+str(sandbox_job.id))
            new_jobs['dynamic'] = str(sandbox_job.id)
            sandbox_body = {
                'uuid':id,
                'ext_id':ext_id,
                'start_time':str(sandbox_job.enqueued_at),
                'job_id':str(sandbox_job.id),
                'time_limit':time_limit,
                'urls':[],
            }

            try:
                es.index(index='sandbox_data',body=sandbox_body)
                print("\x1b[32m[+] Extension mitm data index created in ES: \033[1;0m"+ext_id)
            except:
                print("Failed to create extension mitm data index")
        return json.dumps(new_jobs)
        #return redirect('/report/'+ext_id)

@app.route('/status/<job_id>')
def job_status(job_id):
    job = q.fetch_job(job_id)
    if job is None:
        response = {'status': 'unknown'}
    else:
        response = {
            'status': job.get_status(),
            'result': job.result,
        }
        if job.is_failed:
            response['message'] = job.exc_info.strip().split('\n')[-1]
    return json.dumps(response)

@app.route('/search', methods=['POST'])
def search():
    if not session.get('logged_in'):
        return render_template('login.html')
    elif not es:
        return "Elasticsearch database error"
    else:
        if not es.ping():
            flash('Error: The elasticsearch database is not connected.')
            return redirect(url_for('home'))
        else:
            es_status = True
        # Get search query
        keyword = request.form['keyword']
        keyword = str(keyword)
        sandbox_search = False
        exts = []
        url_data = []
        search_fields = []
        if request.form.get("static_urls"):
            search_fields.append("urls")
        if request.form.get("ext_names"):
            search_fields.append("name")
        if request.form.get("permissions"):
            search_fields.append("permissions")
        if request.form.get("sandbox_urls"):
            sandbox_search = True

        if sandbox_search:
            ext_search = {
                "query": {
                    "query_string" : {
                        "query" : keyword,
                         "default_field": "urls"
                    }
                }

            }
            ext_sandbox = es.search(index="sandbox_data", body=ext_search)
            ext_sandboxs = ext_sandbox['hits']['hits']
            for sandbox in ext_sandboxs:
                if sandbox['_source']['ext_id'] not in exts:
                    exts.append(sandbox['_source']['ext_id'])
                    print("Found sandbox url matches")
            # Filter dups
            exts = sorted(set(exts))
            for ext in exts:
                search_obj = {'query': {'match': {'ext_id': ext}}}
                ext_res = es.search(index="crx", body=search_obj)
                for hit in ext_res['hits']['hits']:
                    if ext == hit['_source']['ext_id']:
                        results = hit['_source']
                        url_data.append(results)

        if search_fields != [] or not sandbox_search:
            # build search for elasticsearch
            search_object = { "query": {"multi_match" : {'query':keyword, 'type':'phrase', 'fields':search_fields}}}
            # query es
            res = es.search(index="crx", body=search_object,size=1000)
            for hit in res['hits']['hits']:
                row = []
                exts.append(hit['_source']['ext_id'])
            # Filter dups
            exts = sorted(set(exts))
            for ext in exts:
                for hit in res['hits']['hits']:
                    if ext == hit['_source']['ext_id']:
                        results = hit['_source']
                        #print("match: "+str(hit['_source']['ext_id']))
                        url_data.append(results)

        return render_template('results.html', url_data=url_data,keyword=keyword,es_status=es_status)

@app.route('/report/<ext>')
def report(ext):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        # build search for elasticsearch
        ext_search = {'query': {'match': {'ext_id': ext}}}
        ext_res = es.search(index="crx", body=ext_search)
        for hit in ext_res['hits']['hits']:
            if ext == hit['_source']['ext_id']:
                # Get ext dynamic data
                ext_sandbox = es.search(index="sandbox_data", body=ext_search)
                ext_sandbox = ext_sandbox['hits']['hits']
                ext_path=os.path.join('static/output', str(hit['_source']['ext_id']))
                return render_template('report.html',icon=hit['_source']['logo'],name=hit['_source']['name'],id=hit['_source']['ext_id'],users=hit['_source']['users'],urls=hit['_source']['urls'],perms=hit['_source']['permissions'],sandboxs=ext_sandbox,es_status=es_status,tree=make_tree(ext_path))
        return("No report found...")

@app.route('/status')
def status():
    """Logout Form"""
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        search = {'query': {'match': {'name': '*'}}}
        if es.indices.exists(index="crx"):
            res = es.search(index="crx", body=search,size=0)
            es_total=res['_shards']['total']
        else:
            es_total=0
        disk_total = len(next(os.walk('static/output'))[1])
        job_results=[]
        jobs = q.jobs
        for j in q.jobs:
            job_results.append([j,j.args[2],j.get_status()])
        #print(str(job_results))
        es_body = {
            "query": {
                "match_all": {}
            }
        }
        scans = []
        try:
            ext_sandboxs = es.search(index="sandbox_data", body={'query': {'match': {'uuid': '*'}}}, size=10)
            scan_results = ext_sandboxs['hits']
            for sandbox in scan_results:
                scans.append(sandbox['_source'])
        except:
            ext_sandboxs = []
        return render_template('status.html', es_status=es_status,es_total=es_total,disk_total=disk_total,jobs=job_results, scans=scans)

@app.route('/update_all')
def update_all():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        update_all_exts(es)
        return render_template('status.html')

@app.route('/update_urls')
def update_urls():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        print("first: update urls list via webstore.py")

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        return render_template('index.html',es_status=es_status)

@app.route('/yara')
def yara():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        return render_template('yara.html',es_status=es_status)

@app.route('/scanning')
def scanning():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        return render_template('scanning.html',es_status=es_status)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                          'favicon.ico',mimetype='image/vnd.microsoft.icon')

# Parse script arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Ext Exposed platform ")
    parser.add_argument('-es', help="Load elastic search data",action='store_true', required=False)
    args = parser.parse_args()
    return args

def make_tree(path):
    tree = dict(name=os.path.basename(path), children=[])
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            if os.path.isdir(fn):
                tree['children'].append(make_tree(fn))
            else:
                tree['children'].append(dict(name=name))
    return tree

if __name__ == '__main__':
    args = parse_args()
    if args.es:
        load_es()
    db.create_all()
    app.secret_key = "changethiskey1337"
    app.run(host="127.0.0.1",port=5000,debug=True)

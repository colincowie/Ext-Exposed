import csv, re, os
import hashlib
import argparse
import requests

from flask_wtf import FlaskForm
from elasticsearch import Elasticsearch
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, flash, redirect, render_template, request, session ,url_for

import redis
from rq import Queue

# import my python scripts for extensions
from ext_sandbox import EXT_Sandbox, sandbox_run
from ext_analyze import EXT_Analyze

app = Flask(__name__)
es = Elasticsearch()
r = redis.Redis()
q = Queue(connection=r)

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
            flash('Welcome to CRX Hunt, '+str(name)+'!')

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
        ext_id = ext_id[0]
        # Static Analysis
        print("[!] Queuing sandbox for "+ext_id)
        ext_scan = EXT_Analyze()
        ext_downloads = ext_scan.get_downloads(ext_id)
        ext_urls = ext_scan.run(ext_id)
        ext_perms = ext_scan.get_perms(ext_id)
        ext_name = str(requests.get("https://chrome.google.com/webstore/detail/z/"+ext_id).url.rsplit('/',2)[1]) # use redirect to get ext name from id. todo: add if to check if its a url
        try:
            es.indices.create(index='crx')
        except:
            pass
        body = {
        'ext_id':ext_id,
        'name':ext_name,
        'users':ext_downloads,
        'permissions':ext_perms,
        'urls':ext_urls
        }
        print("[+] Static analysis results:\n"+str(body))
        try:
            es.index(index='crx',body=body)
            print("\x1b[32m[+] Extension Imported to ES: \033[1;0m"+ext_name.rstrip())
        except:
            print("Failed to import ")

        # Sandbox
        time = 60
        jobs = q.jobs
        box = EXT_Sandbox(ext_id, time)
        job = q.enqueue(sandbox_run, box)
        print("[!] Extension enqueued at "+str(job.enqueued_at)+" with job id: "+str(job.id))


        return render_template('index.html', es_status=es_status)


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
        # build search for elasticsearch
        search_object = {'query': {'query_string': {'query': keyword}}}
        # query es
        res = es.search(index="crx", body=search_object,size=1000)
        exts = []
        for hit in res['hits']['hits']:
            row = []
            exts.append(hit['_source']['name'])
        # Filter dups
        exts = sorted(set(exts))
        url_data = []

        for ext in exts:
            for hit in res['hits']['hits']:
                if ext == hit['_source']['name']:
                    results = [hit['_source']['name'], hit['_source']['urls']]
            if results:
                url_data.append(results)

        ext_data = []
        # get es data for ext data
        for ext in exts:
            if ext not in ext_data:
                ext_search = {'query': {'match': {'name': ext}}}
                ext_res = es.search(index="crx", body=ext_search)
                hits = []
                for hit in ext_res['hits']['hits']:
                    if len(hits) < 1:
                        if ext == hit['_source']['name']:
                            hits.append([hit['_source']['ext_id'],hit['_source']['name'],hit['_source']['users']])
                            ext_data.append([hit['_source']['ext_id'],hit['_source']['name'],hit['_source']['users']])
        # strip regex to use the keyword in ui display
        keyword = re.sub(r'\W+', '', keyword)

        return render_template('results.html', url_data=url_data,keyword=keyword,ext_data=ext_data, url_filter=url_filter)

@app.route('/report/<ext>')
def report(ext):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        # Get URLS for ext
        # build search for elasticsearch
        search_object = {'query': {'match': {'extension': ext}}}
        # query es for urls
        res = es.search(index="intel", body=search_object)
        exts = []
        urls = []
        for hit in res['hits']['hits']:
            if ext == hit['_source']['extension']:
                urls = hit['_source']['urls']
        urls = sorted(set(urls))
        print(urls)

        ext_search = {'query': {'match': {'name': ext}}}
        ext_res = es.search(index="crx", body=ext_search)
        for hit in ext_res['hits']['hits']:
            if ext == hit['_source']['name']:
                print("found: "+hit['_source']['ext_id'])
                print(hit['_source']['name'])
                print(hit['_source']['users'])
                return render_template('report.html',name=hit['_source']['name'],id=hit['_source']['ext_id'],users=hit['_source']['users'],urls=hit['_source']['urls'],perms=hit['_source']['permissions'])

        return("No report found...")

@app.route('/status')
def status():
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
        disk_total = len(next(os.walk('output'))[1])
        return render_template('status.html', es_status=es_status,es_total=es_total,disk_total=disk_total)

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
        return render_template('index.html',es_status=True)

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

def load_es():
    print("[!] Deleteing old data")
    es.indices.delete(index='crx', ignore=[400, 404])
    print("[*] Done")
    print("[*] Loading extension data (data.txt) into elasticsearch...")
    with open('data.txt', 'r') as f:
        csv_reader = csv.reader(f, delimiter=',')
        for row in csv_reader:
            print(str("id: "+row[0]))
            print(str("name: "+row[1]))
            print(str("users: "+row[2]))
            body = {
            'ext_id':row[0],
            'name':row[1],
            'users':row[2]
            }
            es.index(index='crx',body=body)

    print("[*] Loading url data (results.csv) into elasticsearch...")
    # load exts and urls


# Parse script arguments
def parse_args():
    parser = argparse.ArgumentParser(description="CRX Hunt platform ")
    parser.add_argument('-es', help="Load elastic search data",action='store_true', required=False)
    args = parser.parse_args()
    return args

def load_user(user_id):
    return User.get(user_id)


if __name__ == '__main__':
    args = parse_args()
    if args.es:
        load_es()
    db.create_all()
    app.secret_key = "123"
    app.run(host="127.0.0.1",port=5000,debug=True)

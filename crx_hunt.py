import re, os, uuid, json, time, redis, hashlib, argparse
import yara
from rq import Queue
from rq.job import Job
from selenium import webdriver
from flask_sqlalchemy import SQLAlchemy
from elasticsearch import Elasticsearch
from sqlalchemy.ext.declarative import declarative_base
from flask import Flask, flash, redirect, render_template, request, session ,url_for, send_from_directory, send_file, Response, make_response
# import my python scripts for extensions
from ext_sandbox import EXT_Sandbox, sandbox_run
from ext_analyze import EXT_Analyze, static_run
from ext_yara import EXT_yara, yara_run

app = Flask(__name__)
es = Elasticsearch()
r = redis.Redis()
q = Queue(connection=r)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crxhunt.db'
app.secret_key = "changethiskey1337"

db = SQLAlchemy(app)
Base = declarative_base()
Base.query = db.session.query_property()

Build_Ver = "Alpha"

class User(db.Model):
    """ Create user table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(), unique=True)
    password = db.Column(db.String())

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

class DetectionRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    """ Create detection rules table"""
    yara = db.Column(db.Text)
    global_rule = db.Column(db.Boolean)
    owner = db.Column(db.String(80))
    name = db.Column(db.String())
    description = db.Column(db.String())
    tag_color = db.Column(db.String())
    enabled = db.Column(db.Boolean)

    hits = []

    def __init__(self, name, owner, global_rule, yara, description, tag_color):
        self.name = name
        self.owner = owner
        self.global_rule = global_rule
        self.yara = yara
        self.description = description
        self.tag_color = tag_color


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
            session['username'] = name
            session['email'] = user.email
            flash('Welcome to Ext Exposed, '+str(name)+'!', "info")

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
            password=hashlib.sha256(request.form["password"].encode("utf-8")).hexdigest(),
            email = request.form['email'],
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
            flash('Error: The elasticsearch database is not connected.',"danger")
            es_status = False
        else:
            es_status = True
        # Get search query
        keyword = request.form['extension']
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
        # set extension name and id
        ext_scan = EXT_Analyze(ext_id)
        ext_name = ext_scan.name
        new_jobs["name"] = ext_name
        new_jobs["ext_id"] = ext_id
        # array for scan log
        static_status = ''
        dynamic_status = ''
        yara_status = ''

        if request.form.get("static") != None:
            # Static Analysis
            print("[!] Queuing static analysis for "+ext_id)
            static_job = q.enqueue(static_run, ext_scan, ext_id, ext_name, result_ttl=6000)
            #print(job.result)
            print("[!] Static enqueued at "+str(static_job.enqueued_at)+" with job id: "+str(static_job.id))
            new_jobs['static'] = str(static_job.id)
            new_jobs['enqueued_at'] = str(static_job.enqueued_at)
            try:
                stat_job = Job.fetch(static_job.id, connection=r)
                static_status = stat_job.get_status()
            except:
                print("[-] Failed to get static job status")
        # Yara scan
        if request.form.get("global_rules") == "on" or request.form.get("my_rules") == "on":
            print("[!] Queuing yara analysis for "+ext_id)
            scan_rules = []
            if request.form.get("global_rules") == "on":
                community_rules = DetectionRule.query.filter_by(global_rule=True).all()
                for r in community_rules:
                    if scan_rules != []:
                        if r.name != scan_rules[0][0] and r.id != scan_rules[0][2]:
                            if r.enabled:
                                scan_rules.append([str(r.name),str(r.yara),str(r.id),str(r.tag_color),str(r.owner)])
                    else:
                        if r.enabled:
                            scan_rules.append([str(r.name),str(r.yara),str(r.id),str(r.tag_color),str(r.owner)])

            else:
                community_rules = None
            if request.form.get("my_rules") == "on":
                user_rules = DetectionRule.query.filter_by(owner=session["username"]).all()
                for r in user_rules:
                    if scan_rules != []:
                        if r.name != scan_rules[0][0] and r.id != scan_rules[0][2]:
                            if r.enabled:
                            scan_rules.append([str(r.name),str(r.yara),str(r.id),str(r.tag_color)])
                    else:
                        if r.enabled:
                            scan_rules.append([str(r.name),str(r.yara),str(r.id),str(r.tag_color)])
            else:
                user_rules = None
            yara_scan = EXT_yara(ext_id)
            yara_job = q.enqueue(yara_run, ext_id, scan_rules, result_ttl=6000)
            #print(job.result)
            print("[!] Yara enqueued at "+str(yara_job.enqueued_at)+" with job id: "+str(yara_job.id))
            new_jobs['yara'] = str(yara_job.id)
            new_jobs['enqueued_at'] = str(yara_job.enqueued_at)

        if request.form.get("sandbox") != None:
            print("[!] Queuing sandbox for "+ext_id)
            # Sandbox
            time_limit = int(request.form.get('time_limit'))
            print("Time limit:"+str(time_limit))
            id = uuid.uuid4()
            box = EXT_Sandbox(ext_id, time_limit)
            sandbox_job = q.enqueue(sandbox_run, box, id, result_ttl=6000)
            #print(job.result)
            print("[!] Dynamic enqueued at "+str(sandbox_job.enqueued_at)+" with job id: "+str(sandbox_job.id))
            new_jobs['enqueued_at'] = sandbox_job.enqueued_at
            try:
                dyn_job = Job.fetch(sandbox_job.id, connection=r)
                dynamic_status = dyn_job.get_status()
            except:
                print("[-] Failed to get static job status")
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

        scan_log_body = {
            'name':new_jobs["name"],
            'ext_id':new_jobs["ext_id"],
            'enqueued_at':new_jobs['enqueued_at'],
            'dynamic_id':new_jobs['dynamic'],
            'dynamic_status':dynamic_status,
            'static_id':new_jobs['static'],
            'static_status':static_status

        }
        try:
            #print(scan_log_body)
            es.index(index='scan_log',body=scan_log_body)
            print("\x1b[32m[+] Extension scan log index created in ES: "+new_jobs["name"]+"\033[1;0m")
        except Exception as e:
            print("[-] Failed to create extension scan log index")
            print(e)
        return new_jobs

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
        print(response)
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
            flash('Error: The elasticsearch database is not connected.',"danger")
            return redirect(url_for('home'))
        else:
            es_status = True
        # Get search query
        keyword = request.form['hunt_query']
        keyword = str(keyword)
        sandbox_search = False
        exts = []
        url_data = []
        search_fields = []
        if request.form.get("static_urls"):
            search_fields.append("urls")
        if request.form.get("ext_names"):
            search_fields.append("name")
            search_fields.append("full_name")
        if request.form.get("ext_ids"):
            search_fields.append("ext_id")
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

        ext_search = {'query':{
            'match': {
                'ext_id': ext
                }
            }
        }
        ext_res = es.search(index="crx", body=ext_search)
        for hit in ext_res['hits']['hits']:
            if ext == hit['_source']['ext_id']:
                # Get ext dynamic data
                try:
                    ext_search = {'query':{
                        'match': {
                            'ext_id': ext
                            }
                    }}
                    ext_sandbox = es.search(index="sandbox_data", body=ext_search)
                    ext_sandbox = ext_sandbox['hits']['hits']
                except Exception as e:
                    print(e)
                    ext_sandbox = []
                ext_path=os.path.join('static/output', str(hit['_source']['ext_id']))

                # Get detection tags
                tag_res = es.search(index="yara_hits", body={'query': {'match': {'ext_id': hit['_source']['ext_id']}}})
                tags = []
                create_new = True
                # check for duplicates
                for tag in tag_res['hits']['hits']:
                    #print(tag['_source']['rule_name'])
                    #print(tag['_source']['tag_color'])
                    tags.append([tag['_source']['rule_name'],tag['_source']['tag_color'],tag['_source']['hits']])
                print(tags)
                return render_template('report.html',icon=hit['_source']['logo'],full_name=hit['_source']['full_name'],name=hit['_source']['name'],id=hit['_source']['ext_id'],users=hit['_source']['users'],urls=hit['_source']['urls'],perms=hit['_source']['permissions'],sandboxs=ext_sandbox,es_status=es_status,tags=tags,tree=make_tree(ext_path))
        return("No report found...")

@app.route('/status')
def status():
    """Logout Form"""
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
            es_total = 0
            scan_results = []
        else:
            es_status = True
            if es.indices.exists(index="crx"):
                res = es.search(index="crx", q="*", size=100)
                es_total=res['hits']['total']['value']
            else:
                es_total=0
            scans = es.search(index="scan_log", q="*",size=100)
            scan_results = scans['hits']['hits']
        for scan_res in scan_results:
            scan_job = scan_res['_source']
            print(scan_job)
            if scan_job['static_id']:
                try:
                    job = Job.fetch(scan_job['static_id'], connection=r)
                    print('Status: %s' % job.get_status())
                    status_update = {
                        'doc':{
                            'static_status':job.get_status()
                            }
                    }
                    try:
                        es.update(index="scan_log",id=scan_res['_id'],body=status_update)
                    except Exception as e:
                        print(e)
                        print("did not update status")
                except:
                    print("[-] failed finding job")

        disk_total = len(next(os.walk('static/output'))[1])
        job_results=[]
        jobs = q.jobs
        try:
            for j in q.jobs:
                job_results.append([j,j.args[2],j.get_status()])
        except:
            print("[*] No jobs")

        user_count = db.session.execute('select count(id) as c from user').scalar()
        return render_template('status.html', es_status=es_status,user_count=user_count, es_total=es_total,disk_total=disk_total,jobs=job_results, scans=scan_results, ver=Build_Ver)

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
    #DetectionRule.__table__.drop(db.engine)
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        return render_template('index.html',es_status=es_status)

@app.route('/yara')
def detections():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True
        user_rules = DetectionRule.query.filter_by(owner=session["username"]).all()
        community_rules = DetectionRule.query.filter_by(global_rule=True).all()
        # Update detection hits
        for rule in user_rules:
            ext_matches = []
            tag_res = es.search(index="yara_hits", body={'query': {'match': {'rule_id': rule.id}}})
            for tag in tag_res['hits']['hits']:
                ext_matches.append(tag['_source']['ext_id'])
            rule.hits = ext_matches
            db.session.commit()
        for rule in community_rules:
            ext_matches = []
            tag_res = es.search(index="yara_hits", body={'query': {'match': {'rule_id': rule.id}}})
            for tag in tag_res['hits']['hits']:
                ext_matches.append(tag['_source']['ext_id'])
            rule.hits = ext_matches
            db.session.commit()

        return render_template('yara.html',es_status=es_status, user_rules=user_rules, community_rules=community_rules)

@app.route('/yara/toggle', methods=['POST'])
def update_enabled():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        state = request.form['state']
        rule_id = request.form['rule_id']
        db_rule = DetectionRule.query.filter_by(id=rule_id).first()
        if session["username"] == db_rule.owner:
            if state == "on":
                db_rule.enabled = True
            else:
                db_rule.enabled = False
            print("rule status: "+str(db_rule.enabled))
            db.session.commit()
        return "done"


@app.route('/user')
def user_page():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        if not es.ping():
            es_status = False
        else:
            es_status = True

    username = session['username']
    email = session['email']

    return render_template('user.html',es_status=es_status, user=username, email=email)

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
@app.route('/yara/update', methods=['POST'])
def yara_update():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        code_id = "code_"+request.form['rule_id']
        updated_rule = request.form[code_id]
        try:
            yara.compile(source=updated_rule)
        except Exception as e:
            flash('Yara rule error: '+str(e),"danger")
            print(e)
            return redirect(url_for('detections'))
        community_rule = False
        try:
            if request.form['communitySwitch'] == "on":
                community_rule = True
        except:
            community_rule = False
        rule_id = request.form['rule_id']
        db_rule = DetectionRule.query.filter_by(id=rule_id).first()
        if session["username"] == db_rule.owner:
            db_rule.global_rule = community_rule
            db_rule.yara = updated_rule
            db_rule.tag_color = request.form['tag_color']
            db.session.commit()
        flash('Rule updated', "info")

        return redirect(url_for('detections'))
@app.route('/yara/edit', methods=['POST'])
def yara_edit():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        new_rule = request.form['new_rule']
        try:
            yara.compile(source=new_rule)
        except Exception as e:
            flash('Yara rule error: '+str(e),"danger")
            print(e)
            return redirect(url_for('detections'))
        community_rule = False
        try:
            if request.form['communitySwitch'] == "on":
                community_rule = True
        except:
            community_rule = False

        new_rule = DetectionRule(
            name = request.form['rule_name'],
            owner= session['username'],
            global_rule = community_rule,
            yara = request.form['new_rule'],
            description = request.form['rule_desc'],
            tag_color = request.form['tag_color']
            )
        db.session.add(new_rule)
        db.session.commit()
        flash('New rule added, '+str(request.form['rule_name'])+'!', "info")

        return redirect(url_for('detections'))

@app.route('/yara/delete', methods=['POST'])
def yara_delete():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        rule_id = request.form['rule_id']
        rule = DetectionRule.query.filter_by(id=rule_id).first()
        if session["username"] == rule.owner:
            try:
                db.session.delete(rule)
                db.session.commit()
            except Exception as e:
                flash("yara delete error: "+str(e),"danger")
        return redirect(url_for('detections'))

@app.route('/ext_file', methods=['POST'])
def file_read():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        file_location = request.form['file_path']
        fs = open(file_location, 'r', encoding='utf8')
        file_source = fs.read()
        resp = make_response(file_source)
        if file_location.endswith('.js'):
            resp.headers['fileType'] = 'js'
        elif file_location.endswith('.html'):
            resp.headers['fileType'] = 'html'
        elif file_location.endswith('.css'):
            resp.headers['fileType'] = 'css'
        elif file_location.endswith('.json'):
            resp.headers['fileType'] = 'json'
        elif file_location.endswith('.xml'):
            resp.headers['fileType'] = 'xml'
        else:
            resp.headers['fileType'] = ''
        return resp

@app.route('/urls/<ext_id>')
def urls_download(ext_id):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        print("[*] static url report requested for "+ext_id)
        dir = 'reports/'+ext_id
        file = 'static_urls.csv'
        return send_from_directory(directory=dir,filename=file)

@app.route('/sandboxes/<ext_id>/<uuid>')
def sandbox_download(ext_id, uuid):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        def get_sandbox():
            ext_search = {
                "query": {
                    "bool": {
                      "should": [
                        {
                          "match": {
                            "ext_id": ext_id
                          }
                        },
                        {
                          "match": {
                            "uuid": uuid
                          }
                        }
                      ]
                    }
                  }
            }
            ext_sandbox = es.search(index="sandbox_data", body=ext_search)
            ext_sandbox = ext_sandbox['hits']['hits']
            for report in ext_sandbox:
                if report['_source']['uuid'] == uuid:
                    print("MATCH!")
                    print(report['_source']['uuid'])
                    for url in report['_source']['urls']:
                        yield url[0]+","+url[1]+"\n"
        return Response(get_sandbox(), mimetype='text/csv')

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

def create_es():
    es = Elasticsearch()
    mapping = {"mapping":{
       "properties":{
         "ext_id":{"type":"text"},
         "ext_name":{"type":"text"},
         "full_name":{"type":"text"},
         "timestamp":{"type":"date"},
         "logo":{"type":"text"},
         "users":{"type":"text"},
         "permissions":{"type":"json"}
       }
      }}
    try:
        print("[*] Creating elasticsearch index's ")
        es.indices.create(index='crx',body=mapping)
        print("[*] Created index crx")
    except:
        pass
    try:
        es.indices.create(index='scan_log')
        print("[*] Created index scan_log")
    except:
        pass
    try:
        es.indices.create(index='yara_hits')
        print("[*] Created index yara_hits")
    except:
        pass
    try:
        es.indices.create(index='sandbox_data')
        print("[*] Created index sandbox_data")
    except:
        pass

if __name__ == '__main__':
    args = parse_args()
    if args.es:
        load_es()
    db.create_all()
    create_es()
    app.run(host="0.0.0.0",port=1337,debug=True)

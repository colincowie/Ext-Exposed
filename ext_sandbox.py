11# @th3_protoCOL
import os, sys, time, asyncio, threading, requests, zipfile, json
from selenium import webdriver
from multiprocessing import Process
from mitmproxy.options import Options
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.utils import human
from elasticsearch import Elasticsearch

from flask import current_app

from pyvirtualdisplay import Display

class EXT_Sandbox():
    def __init__(self,ext_id,time_limit):
        self.ext_id = ext_id
        self.time = time_limit
        # Set up output dirs
        if not os.path.exists('static/output'):
            os.makedirs('static/output')
        if not os.path.exists("reports"):
            os.makedirs("reports")
        if not os.path.exists("reports/"+self.ext_id+"/"):
            os.makedirs("reports/"+self.ext_id+"/")


    def download_ext(self, id):
        # Download extension webstore url
        download_url = "https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown&prodversion=81.0.4044.138&acceptformat=crx2,crx3&x=id%3D" + id + "%26uc"
        print("[*] Downloading extension with id: "+id)
        r = requests.get(download_url, allow_redirects=True)

        # Save output of download
        if r.status_code == 200 :
            # Save ext to .crx file
            crx = os.path.join('static/output', id)+'.crx'
            open(crx, 'wb').write(r.content)
            print("[*] Unzipping Extension")
            try:
                with zipfile.ZipFile(crx, 'r') as zip_ref:
                    zip_ref.extractall(crx[:-4])
                os.remove(crx)
            except Exception as e:
                print("[-] Unzip Error")
                print(e)
                print(download_url)
                pass
            return True
        elif r.status_code == 204:
            print("[-] HTTP 204: No Content.")
            return False
        else:
            print("[-] Error! Status Code: "+str(r.status_code))
            return False

    def run(self):
        id = self.ext_id
        requests.put('http://localhost:9200/mitm')
        mitm = self.start_mitm()
        ext_download = self.download_ext(id)
        if ext_download:
            print("[*] Creating virtual display")
            try:
                display = Display(visible=0, size=(800, 600))
                display.start()
                print("[*] Display started")
            except:
                print("[-] Error! You need to install xvfb (linux package)")
            # Create the webdriver with proxy and extension
            options = webdriver.ChromeOptions()
            # Load chrome extension
            options.add_argument('load-extension='+os.path.abspath("static/output")+'/'+str(id));
            options.add_argument('--proxy-server=127.0.0.1:8080')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--allow-running-insecure-content')
            options.add_argument('--no-sandbox')
            options.add_experimental_option("detach", True)
            print("[*] Creating chrome driver")
            #driver = webdriver.Chrome(executable_path="/bin/chromedriver",options=options)
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.time)
            print("\u001b[40m\u001b[32m[↓]\u001b[0m\u001b[40m Sandbox Network Request \u001b[32m[↓]\u001b[0m\u001b[0m")
            failed = False
            try:
                driver.get("chrome://newtab")
                print("[*] Navigated to chrome://newtab")
            except:
                failed = True
                print("[-] Erorr: Likely timeout")
            try:
                driver.get("https://google.com")
                print("[*] Navigated to https://google.com")
            except:
                failed = True
                print("[-] Erorr: Likely timeout")
            if not failed:
                print("[*] Sleeping while extension is running")
                time.sleep(self.time)
            try:
                driver.close()
                driver.quit()
            except:
                print("[?] Error: browser is already closed")
            try:
                display.stop()
            except:
                pass
            print('[*] Shutting down mitmproxy...')
            mitm.shutdown()
            print('[*] Uploading results to elasticsearch....')
            data = []
            output = "reports/"+id+"/mitm_urls.json"
            with open(output, 'r') as f:
                data = json.load(f)
                #csv_reader = csv.reader(f, delimiter=',')
                #for row in csv_reader:
                #    data.append(row)
            return data

    def start_mitm(self):
            asyncio.set_event_loop(asyncio.new_event_loop())
            print('[*] Starting mitmproxy on 127.0.0.1:8080')
            options = Options(listen_host='127.0.0.1', listen_port=8080, http2=True)
            m = DumpMaster(options, with_termlog=False, with_dumper=False)
            config = ProxyConfig(options)
            m.server = ProxyServer(config)
            addon = MitmAddon(self.ext_id)
            m.addons.add(addon)
            # run mitmproxy in backgroud
            loop = asyncio.get_event_loop()
            t = threading.Thread( target=loop_in_thread, args=(loop,m) )
            t.start()
            return m

# Addon class for Mitmproxy recording
class MitmAddon(object):
    def __init__(self,ext_id):
        self.ext_id = ext_id
        self.output = "reports/"+self.ext_id+"/mitm_urls.json"
        if os.path.exists("reports/"+self.ext_id+"/mitm_urls.json"):
            try:
                os.remove("reports/"+self.ext_id+"/mitm_urls.json")
            except Exception as e:
                print(e)
        with open(self.output, 'a') as json_file:
            json.dump({'traffic':[]},json_file)

    # convert to json and save new file for every sandbox
    def request(self, flow):
        print("\033[0;35m[request] \033[0m"+str(flow.request.method),str(flow.request.url),str(len(flow.request.content)) )
        request_data = {
            'type':'request',
            'method':str(flow.request.method),
            'url':str(flow.request.url),
            'content size':str(len(flow.request.content))
        }
        with open(self.output, 'r+') as json_file:
            data = json.load(json_file)
            temp = data["traffic"]
            temp.append(request_data)
        with open(self.output, 'r+') as json_file:
            json.dump(data, json_file, indent=4)

    def response(self, flow):
        if flow.response.raw_content:
            response_body_size = len(flow.response.raw_content)
        else:
            response_body_size = 0
        print(flow.server_conn.address)
        print("\033[0;34m[response] \033[0m"+str(flow.response.status_code)+', '+str(flow.server_conn.ip_address[0])+', '+str(flow.server_conn.ip_address[1])+', '+str(flow.response.headers.get('Content-Type', ''))+', '+str(response_body_size))
        response_data = {
            'type':'response',
            'status_code':flow.response.status_code,
            'server_domain':str(flow.server_conn.address[0]),
            'server_ip':str(flow.server_conn.ip_address[0]),
            'server_port':str(flow.server_conn.ip_address[1]),
            'headers':str(flow.response.headers.get('Content-Type', '')),
            'response_body_size':str(response_body_size)
        }
        if 'application/json' in response_data['headers']:
            response_data['content'] = str(flow.response.content.decode('utf-8'))

        with open(self.output, 'r+') as json_file:
            data = json.load(json_file)
            temp = data["traffic"]
            temp.append(response_data)
        with open(self.output, 'r+') as json_file:
            json.dump(data, json_file, indent=4)
            #f.write("--------")
            #for k, v in flow.request.headers.items():
            #    f.write('\n' + str(flow.request.content.decode('utf-8')) + '\n')
            #    for k, v in flow.response.headers.items():
            #        f.write('\n' + str(flow.response.content.decode('utf-8')) + '\n')

# function used for proxy async - source: https://gist.github.com/BigSully/3da478792ee331cb2e5ece748393f8c4
def loop_in_thread(loop, m):
    asyncio.set_event_loop(loop)
    m.run_loop(loop.run_forever)

def sandbox_run(box, uuid, scanlog_id):
    es = Elasticsearch()
    try:
        es.indices.create(index='sandbox_data')
    except:
        pass
    # Pull scan_log es record:
    update_body = {'query': {'match': {'scanlog_id': scanlog_id}}}
    ext_res = es.search(index="scan_log", body=update_body)
    # Update es scan log
    scan_log_body = {'doc':{'dynamic_status':'Started'}}
    for hit in ext_res['hits']['hits']:
        if len(hit) > 0:
            try:
                es.update(index='scan_log',body=scan_log_body,id=hit['_id'])
            except Exception as e:
                print("[-] scan update err")
                print(e)

    url_data = box.run()
    print("[!] Updating ES record")

    ext_id = str(box.ext_id)
    res = es.search(index='sandbox_data',body={'query':{'match':{'uuid':uuid}}})
    try:
        es_data = res['hits']['hits'][0]
    except:
        print("[*] no urls found ")
        result_status = "No Results"

    sandbox_body = {"doc": {"urls":url_data}}

    # Update scan log again
    if url_data == None:
        result_status = "Error"
    elif len(url_data) > 0:
        result_status = "Finished"


    scan_log_body = {'doc':{'dynamic_status':result_status}}

    for hit in ext_res['hits']['hits']:
        print(hit)
        if len(hit) > 0:
            print("[*] Updating scan "+str(scanlog_id))
            try:
                es.update(index='scan_log',body=scan_log_body,id=hit['_id'])
            except Exception as e:
                print("[-] scan update err")
                print(e)


    try:
        es.update(index='sandbox_data', id=es_data['_id'], body=sandbox_body)
        return True
    except:
        return False



if __name__ == "__main__":
    ext = input("[!] Please provide a chrome extension id: ")
    # Create instance of the sandbox class and run with an extension id
    box = EXT_Sandbox(ext, 60)
    box.run()

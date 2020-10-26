# @th3_protoCOL
import os, sys, time, asyncio, threading, requests, zipfile, json
from selenium import webdriver
from multiprocessing import Process
from mitmproxy.options import Options
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster
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
            options.add_argument('--proxy-bypass-list=*')
            options.add_argument('--allow-running-insecure-content')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            #options.add_experimental_option("detach", True)
            print("[*] Creating chrome driver")
            driver = webdriver.Chrome(options=options)
            time.sleep(3)
            print("\u001b[40m\u001b[32m[↓]\u001b[0m\u001b[40m Sandbox Network Request \u001b[32m[↓]\u001b[0m\u001b[0m")
            driver.get("chrome://extensions/?id="+id)
            driver.get("https://google.com")
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
            output = "reports/"+id+"/mitm_urls.txt"
            data = []
            url_file = open(output, 'rw')
            for line in url_file.readlines():
                verb = line.split()[0]
                url = line.split()[1]
                data.append([verb,url])
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
        self.num = 1

    def request(self, flow):
        output = "reports/"+self.ext_id+"/mitm_urls.txt"
        flow.request.headers["count"] = str(self.num)
        print("\033[0;35m[request] \033[0m"+flow.request.url)
        # Save reques to data (format [VERB, url])
        with open(output, 'a') as f:
            f.write(str(flow.request.method) + ' ' + str(flow.request.url) + ' ' + '\n')

    def response(self, flow):
        self.num = self.num + 1
        flow.response.headers["count"] = str(self.num)

        url = flow.request.url

        output = "reports/"+self.ext_id+"/mitm_content.txt"
        with open(output, 'a') as f:
            f.write(str(flow.request.method) + ' ' + str(flow.request.url) +  '\n')
            f.write("--------")
            for k, v in flow.request.headers.items():
                f.write('\n' + str(flow.request.content.decode('utf-8')) + '\n')
                for k, v in flow.response.headers.items():
                    f.write('\n' + str(flow.response.content.decode('utf-8')) + '\n')

# function used for proxy async - source: https://gist.github.com/BigSully/3da478792ee331cb2e5ece748393f8c4
def loop_in_thread(loop, m):
    asyncio.set_event_loop(loop)
    m.run_loop(loop.run_forever)

def sandbox_run(box, uuid):
    url_data = box.run()
    print("[!] Updating ES record")
    es = Elasticsearch()
    try:
        es.indices.create(index='sandbox_data')
    except:
        pass
    ext_id = str(box.ext_id)
    res = es.search(index='sandbox_data',body={'query':{'match':{'uuid':uuid}}})
    es_data = res['hits']['hits'][0]
    #print("ES found "+str(es_data))
    sandbox_body = {"doc": {"urls":url_data}}
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

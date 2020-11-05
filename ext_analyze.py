# @th3_protoCOL
import os, re, csv, time, json, jsbeautifier, requests, zipfile, urllib
from tqdm import tqdm
from bs4 import BeautifulSoup
from elasticsearch import Elasticsearch


class EXT_Analyze():
    def __init__(self, id):
        self.id = id
        ext_name = str(requests.get("https://chrome.google.com/webstore/detail/z/"+id).url.rsplit('/',2)[1]) # use redirect to get ext name from id. todo: add if to check if its a url
        self.name = ext_name
        self.full_name = ""
        if not os.path.exists('static/output'):
            os.makedirs('static/output')
        pass

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

    def get_urls(self, id):
        found_urls = []
        if not os.path.exists("reports"):
            os.makedirs("reports")
        if not os.path.exists("reports/"+id+"/"):
            os.makedirs("reports/"+id+"/")

        print("\033[93m[*]\033[00m Starting analysis on "+id)
        results = [['Extension ID, File, URL']]
        ext_dir = os.path.join("static/output", id)
        files = os.scandir(ext_dir)
        for (root,dirs,files) in os.walk(ext_dir, topdown=True):
            # Scan files in  dirs
            for file in files:
                # Todo: add hash checks
                if file.endswith(".js") or file.endswith(".json"):
                    print("[*] Extrating links from "+str(file))
                    script = open(os.path.join(root,file), "r", encoding="utf8")
                    try:
                        content = jsbeautifier.beautify(script.read())
                        # This regex only matches with these protocols. adding a ? results in some false positives with javascript varibles
                        matches = re.findall('(http://|ftp://|ws://|https://|ws://|file://)([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?', content)
                        #matches = re.findall(r'(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))',content)
                        matches = list(dict.fromkeys(matches))
                        for url in matches:
                            # Todo: upload to ES
                            # The regex returns a tuplet so some things are done to clear the url
                            found_urls.append((' '.join(url)).replace(" ", ""))
                            with open('reports/'+id+'/static_urls.csv','a', newline='') as csvfile:
                                obj=csv.writer(csvfile)
                                obj.writerow([str(id), str(file),(' '.join(url)).replace(" ", "")])
                                csvfile.close()
                    except Exception as e:
                        print("\033[91m[-] Error: \033[1;0mcould not decode.")
                        print(e)
        print('\033[32m[!]\033[0m Total URLs found: '+str(len(found_urls)))
        return found_urls

    def get_perms(self, id):
        # get perms
        file_path = 'static/output/'+id+'/manifest.json'
        perms = []
        icon = ""
        with open(file_path,'r') as manifest:
            data = None
            data = json.load(manifest)
            #print("Data loading error")
            if data is not None:
                if 'permissions' not in data:
                    print("No perms found ")
                    perms =  None
                else:
                    perms = data['permissions']
                # Get default icon path
        return perms
    # to do: user
    def get_icon(self,id):
        # get perms
        file_path = 'static/output/'+id+'/manifest.json'
        icon = ""
        with open(file_path,'r') as manifest:
            data = None
            data = json.load(manifest)
            #print("Data loading error")
            if data is not None:
                try:
                    icon = data['browser_action']['default_icon']
                except:
                    print("default_icon not found ")
                    icon =  ""
                    print(data)
        return icon

    def get_downloads(self, id):
        ext_page = None
        # Google redirects as long as you have the id!
        url = "https://chrome.google.com/webstore/detail/z/"+id
        try:
            ext_page = requests.get(url)
        except Exception as e:
            print("\033[91m[-] Error: \033[1;0m")
            print(e)
            return None
        # set up soup for some parsing
        soup = BeautifulSoup(ext_page.content,features="lxml")
        full_name = soup.find(itemprop="name").get("content")
        self.full_name = full_name
        # Parse the <meta> tag for the exact number, remove junk characters and round it.
        download_tag = soup.find(itemprop="interactionCount")
        if download_tag is not None:
            download_tag = download_tag.get("content")
            download_tag = download_tag.rstrip()
            print(download_tag)
            download_count = download_tag.rsplit(':',1)[1]
            print(download_count)
        else:
            download_count = 0
        return download_count

    def run(self, id):
        self.download_ext(id)
        urls = self.get_urls(id)
        return urls

    def name(self):
        return str(self.name)

def static_run(ext_scan, ext_id, name):
    es = Elasticsearch()
    ext_downloads = ext_scan.get_downloads(ext_id)
    ext_urls = ext_scan.run(ext_id)
    ext_perms = ext_scan.get_perms(ext_id)
    ext_name = name
    logo_path = ext_scan.get_icon(ext_id)
    if not isinstance(logo_path, str):
        try:
            logo_path=logo_path['32']
        except:
            try:
                logo_path=logo_path['24']
            except:
                try:
                    logo_path=logo_path['64']
                except:
                    logo_path=logo_path['128']
    try:
        es.indices.create(index='crx')
    except:
        pass

    ext_search = {'query': {'match': {'ext_id': ext_id}}}
    ext_res = es.search(index="crx", body=ext_search)
    if ext_res['hits']['hits']:
        for hit in ext_res['hits']['hits']:
            if ext_id == hit['_source']['ext_id']:
                print("Deleting: "+str(hit['_source']))
                es.delete(index="crx",id=hit['_id'])
    body = {
    'ext_id':ext_id,
    'name':ext_name,
    'users':ext_downloads,
    'permissions':ext_perms,
    'logo':logo_path,
    'full_name':self.full_name
    'urls':ext_urls
    }
    print("[+] Static analysis results:\n"+str(body))

    # check if ext is in database:
    dup_search = {'query': {'match': {'ext_id': ext_id}}}
    ext_res = es.search(index="crx", body=dup_search)
    hits = []
    uploaded = False
    # check for duplicates
    try:
        for hit in ext_res['hits']['hits']:
            if len(hits) > 0:
                print("[*] extension "+str(ext_id)+" is already in the database. Attempting to update")
                try:
                    es.update(index='crx',body=body,id=hit['_id'])
                except:
                    pass
    except:
        pass
    try:
        es.index(index='crx',body=body)
        print("\x1b[32m[+] Extension Imported to ES: \033[1;0m"+ext_id)
        return True
    except Exception as e:
        print("[-] Failed to import to ES")
        print(e)
        return False


if __name__ == "__main__":
    ext = input("[!] Please provide a chrome extension id: ")
    ext_scan = EXT_Analyze(ext)
    print("[*] Total Downloads: "+str(ext_scan.get_downloads(ext)))
    ext_scan.run(ext)
    print("[*] Permissions: ")
    print(ext_scan.get_perms(ext))

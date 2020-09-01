# @th3_protoCOL 
import os, re, csv, time, jsbeautifier, requests, zipfile

class EXT_Analyze():
    def __init__(self):
        if not os.path.exists('output'):
            os.makedirs('output')
        pass

    def download_ext(self, id):
        # Download extension webstore url
        download_url = "https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown&prodversion=81.0.4044.138&acceptformat=crx2,crx3&x=id%3D" + id + "%26uc"
        print("[*] Downloading extension with id: "+id)
        r = requests.get(download_url, allow_redirects=True)

        # Save output of download
        if r.status_code == 200 :
            # Save ext to .crx file
            crx = os.path.join('output', id)+'.crx'
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

        print("\033[93m[*]\033[00m Starting analysis on "+id)
        results = [['Extension ID, File, URL']]
        dir = os.path.abspath("output")
        for r, d, f in os.walk(dir):
                for file in f:
                    # Todo: add hash checks
                    if file.endswith(".js") or file.endswith(".json"):
                        print("[*] Extrating links from "+str(file))
                        script = open(os.path.join(r, file), "r", encoding="utf8")
                        try:
                            content = jsbeautifier.beautify(script.read())
                            # Todo: change the url extracting!
                            # This regex only matches with these protocols. adding a ? results in some false positives with javascript varibles
                            matches = re.findall('(http://|ftp://|ws://|https://|file://)([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?', content)
                            matches = list(dict.fromkeys(matches))
                            for url in matches:
                                # Todo: upload to ES
                                # The regex returns a tuplet so some things are done to clear the url
                                found_urls.append((' '.join(url)).replace(" ", ""))
                                with open('results.csv','a', newline='') as csvfile:
                                    obj=csv.writer(csvfile)
                                    obj.writerow([str(id),str(file), (' '.join(url)).replace(" ", ""), str(id)])
                                    csvfile.close()
                        except Exception as e:
                            print("\033[91m[-] Error: \033[1;0mcould not decode.")
                            print(e)

        found_urls = list(dict.fromkeys(found_urls))
        print("\033[94m[+]\n[+]\033[00m Report on:  "+id+"\n\033[94m[+]\033[00m")
        print("[*] Found "+str(len(found_urls))+" URLs!")
        found_urls.sort()
        for url in found_urls:
            print("[*] "+ url)

    def run(self, id):
        self.download_ext(id)
        self.get_urls(id)

if __name__ == "__main__":
    ext = input("[!] Please provide a chrome extension id: ")
    ext_scan = EXT_Analyze()
    ext_scan.run(ext)

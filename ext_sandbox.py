# @th3_protoCOL
import os, time, requests, zipfile
from selenium import webdriver

class EXT_Sandbox():
    proxy = '127.0.0.1:8080'

    def __init__(self):
        if not os.path.exists('output'):
            os.makedirs('output')
        pass

    def download_ext(self, id):
        # Download extension
        download_url = "https://clients2.google.com/service/update2/crx?response=redirect&os=win&arch=x86-64&os_arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=unknown&prodversion=81.0.4044.138&acceptformat=crx2,crx3&x=id%3D" + id + "%26uc"
        print("[*] Downloading extension with id: "+id)
        r = requests.get(download_url, allow_redirects=True)

        # Save output of download
        if r.status_code == 200 :
            crx = os.path.join('output', id)+'.crx'
            print("crx path: "+crx)
            open(crx, 'wb').write(r.content)
            print("[*] Unzipping Extension: "+id)
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

    def run(self, id):
        ext_download = self.download_ext(id)
        if ext_download:
            print("[*] Creating chrome webdriver with proxy")
            # Create the webdriver with proxy and extension
            options = webdriver.ChromeOptions()
            # Load chrome extension
            options.add_argument('load-extension='+os.path.abspath("output")+'/'+str(id));
            options.add_argument('--proxy-server='+str(self.proxy))
            options.add_argument('--allow-running-insecure-content')
            options.add_argument('--ignore-certificate-errors')
            options.add_experimental_option("detach", True)

            driver = webdriver.Chrome(options=options)
            driver.get("chrome://extensions/?id="+id)
            time.sleep(3)
            #print(driver.page_source.encode("utf-8"))
            print("[*] Headless browser finished")

if __name__ == "__main__":
     box = EXT_Sandbox()
     box.run("ext_id")

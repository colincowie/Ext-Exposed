# @th3_protoCOL
import os, re, yara
from tqdm import tqdm
from elasticsearch import Elasticsearch

class EXT_yara():
    def __init__(self, id):
        self.id = id
        self.dir = "static/output"

    def scan_ext(self, rule):
        id = self.id
        print("\033[93m[*]\033[00m Starting yara scan for "+id+" with rule: "+str(rule[0]))
        yara_rule = yara.compile(source=rule[1])
        ext_dir = os.path.join(self.dir, id)
        print(ext_dir)
        files = os.scandir(ext_dir)
        matched_files = []
        for (root,dirs,files) in os.walk(ext_dir, topdown=True):
            # Scan files in  dirs
            for file in files:
                print(os.path.join(root,file))
                file_open = open(os.path.join(root,file), "r", encoding="utf8")
                content = file_open
                #print("[*] Yara scan for: "+str(file))
                matches = yara_rule.match(os.path.join(root,file), timeout=60)
                if len(matches) > 0:
                    #print("yara content match: "+str(matches[0].strings))
                    print("[!] Yara match: "+ file + " matches "+str(matches))
                    matched_files.append(os.path.join(root,file))

        return matched_files


    def run(self, rule):
        return self.scan_ext(rule)


def yara_run(ext_id, rules):
    es = Elasticsearch()
    scan = EXT_yara(ext_id)
    try:
        es.indices.create(index='yara_hits')
    except:
        pass

    for rule in rules:
        file_hits = scan.run(rule)
        #print(rule)
        body = {
            'ext_id':ext_id,
            'rule_name':rule[0],
            'rule_id':rule[2],
            'tag_color':rule[3],
            'owner':rule[4],
            'hits':file_hits,
        }

        dup_search = {'query': {'match': {'ext_id': ext_id}}}
        ext_res = es.search(index="yara_hits", body=dup_search)
        hits = []
        create_new = True
        # check for duplicates
        for hit in ext_res['hits']['hits']:
            create_new = True
            if (hit['_source']['rule_name'] == rule[0]):
                if (hit['_source']['rule_id'] == rule[2]):
                    create_new = False
                    try:
                        uniq_hits = list(set(file_hits))
                        new_hits = hit['_source']['hits']
                        for new_file in uniq_hits:
                            if new_file not in new_hits:
                                new_hits.append(new_file)
                                print ("[!] New tagged files after update: "+ str(new_hits))

                                body = {
                                    "doc": {'hits':new_hits}
                                }
                                es.update(index='yara_hits',body=body,id=hit['_id'])

                    except Exception as e:
                        print("[-] Error could not update yara entry in es")
                        print(e)
        if create_new:
            if len(file_hits) > 0:
                try:
                    es.index(index='yara_hits',body=body)
                    print("\x1b[32m[+] Extension Imported to yara_hits: \033[1;0m"+ext_id)
                    return True
                except Exception as e:
                    print("[-] Failed to import to ES")
                    print(e)
                    return False
    else:
        print("[*] No new files tagged")

    return True

def retrohunt_run(rule, type, es_id):
    es = Elasticsearch()
    if type == 'files':
        print('[!] Preparing yara scan of extension')
        # Get len of list dir, set max number
        scan_length = len(os.listdir('static/output'))
        index_counter = 0
        matches = []
        for ext_id in os.listdir('static/output'):
            index_counter = index_counter + 1
            scan = EXT_yara(str(ext_id))
            file_hits = scan.run(rule)
            # setup body for yara_hits
            body = {
                'ext_id':ext_id,
                'rule_name':rule[0],
                'rule_id':rule[2],
                'tag_color':rule[3],
                'owner':rule[4],
                'hits':file_hits
            }
            # Update yara_hits index for ext id
            if file_hits is not []:
                uniq_hits = list(set(file_hits))
                if uniq_hits != []:
                    matches.append([ext_id, uniq_hits])
                dup_search = {'query': {'match': {'ext_id': ext_id}}}
                ext_res = es.search(index="yara_hits", body=dup_search)
                hits = []
                create_new = True
                # check for duplicates
                for hit in ext_res['hits']['hits']:
                    create_new = True
                    if (hit['_source']['rule_name'] == rule[0]):
                        if (hit['_source']['rule_id'] == rule[2]):
                            create_new = False
                            try:
                                new_hits = hit['_source']['hits']
                                for new_file in uniq_hits:
                                    if new_file not in new_hits:
                                        new_hits.append(new_file)
                                        print ("[!] New tagged files after update: "+ str(new_hits))

                                        body = {
                                            "doc": {'hits':new_hits}
                                        }
                                        es.update(index='yara_hits',body=body,id=hit['_id'])
                            except Exception as e:
                                print("[-] Error could not update yara entry in es")
                                print(e)
                if create_new:
                    if len(file_hits) > 0:
                        try:
                            es.index(index='yara_hits',body=body)
                            print("\x1b[32m[+] Extension Imported to yara_hits: \033[1;0m"+ext_id)
                        except Exception as e:
                            print("[-] Failed to import to ES")
                            print(e)

            progress = (index_counter / scan_length) * 100
            retro_body = {
                "doc": {'progress':progress,'hits':matches}
            }
            es.update(index='retro_log',body=retro_body,id=es_id)
    if type == 'network':
        print("[*] Starting Network Yara Scan")
        matches = []
        # Get len of list dir, set max number
        scan_length = len(os.listdir('reports'))
        index_counter = 0
        for ext_id in os.listdir('reports'):
            index_counter = index_counter + 1
            scan = EXT_yara(str(ext_id))
            scan.dir = 'reports'
            print("[*] Net Data Scan for :"+str(ext_id))
            file_hits = scan.run(rule)
            if file_hits is not []:
                uniq_hits = list(set(file_hits))
                if uniq_hits != []:
                    matches.append([ext_id, uniq_hits])
            # Update es index
            progress = (index_counter / scan_length) * 100
            retro_body = {
                "doc": {'progress':progress,'hits':matches}
            }
            es.update(index='retro_log',body=retro_body,id=es_id)

    return True


if __name__ == "__main__":
    ext = input("[!] Please provide a chrome extension id: ")
    scan = EXT_yara(ext)
    scan.run()
    print("[*] Scanning..")

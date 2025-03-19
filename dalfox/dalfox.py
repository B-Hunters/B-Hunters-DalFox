from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import re
from bson.objectid import ObjectId

class dalfox(BHunters):
    """
    B-Hunters-DalFox developed by Bormaa
    """

    identity = "B-Hunters-DalFox"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "paths", "stage": "scan"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def rundalfox(self,data):
        result=[]
        resultarr=[]
        try:
            outputfile=self.generate_random_filename()+".json"
            filename=self.generate_random_filename()+".txt"
            with open(filename, 'wb') as file:
                # for item in data:
                file.write(data)
                
            p1 = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)


            # Command 3: grep -v 'png\|jpg\|css\|js\|gif\|txt'
            p3 = subprocess.Popen(["grep", "-v", "png\|jpg\|css\|js\|gif\|txt"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()

            # Command 4: grep '='
            p4 = subprocess.Popen(["grep", "="], stdin=p3.stdout, stdout=subprocess.PIPE)
            p3.stdout.close()

            # Command 5: uro
            p5 = subprocess.Popen(["uro","--filter","hasparams"], stdin=p4.stdout, stdout=subprocess.PIPE)
            p4.stdout.close()
            p6 = subprocess.Popen(["qsreplace","FUZZ"], stdin=p5.stdout, stdout=subprocess.PIPE)
            p5.stdout.close()
            newlinks=self.checklinksexist(self.subdomain,p6.stdout.read().decode("utf-8"))
            if newlinks==[]:
                return [],[]
            # Command 7: dalfox pipe --deep-domxss --multicast --blind 
            p7 = subprocess.Popen(["dalfox", "pipe", "--deep-domxss", "--multicast","-w",os.getenv("workers_num","300"),"-o",outputfile,"--format","json","--no-color"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            p7.stdin.write('\n'.join(newlinks).encode())
            # p7.stdin.close()

            p6.stdout.close()
            try:
                output, _ = p7.communicate(timeout=7200)  # 120 minutes timeout
            except subprocess.TimeoutExpired:
                p7.kill()
                try:
                    output, _ = p7.communicate(timeout=5)  # Give it a few seconds to fully terminate
                except subprocess.TimeoutExpired:
                    self.log.error("Force-killing DalFox process after failed kill attempt.")
                    p7.terminate()  # Fallback to terminate if kill is insufficient
                    output, _ = p7.communicate()
            # Check if outputfile exists and read it as JSON
            if os.path.exists(outputfile):
                with open(outputfile, 'r') as json_file:
                    json_data = json.load(json_file)
                    # Process the JSON data as needed
                    for item in json_data:
                        if item !={}:
                            result.append({"url":f"{item['method']} {item['data']}","vuln":item['message_str']})
                            resultarr.append(f"{item['method']} {item['data']} Vuln {item['message_str']}")

                # Remove the output file after processing
                os.remove(outputfile)
            os.remove(filename)
        except Exception as e:
            self.log.error(e)
            raise Exception(f"Failed to process {e}")
        return result,resultarr
                    
    def scan(self,url,source):
        data=self.backend.download_object("bhunters",f"{source}_"+self.scanid+"_"+self.encode_filename(url))
        result,resultarr=self.rundalfox(data)
        return result,resultarr
        
    def process(self, task: Task) -> None:
        url = task.payload["data"]
        subdomain=task.payload["subdomain"]
        source=task.payload["source"]
        self.scanid=task.payload_persistent["scan_id"]
        self.log.info("Starting processing new url")
        self.log.warning(url)
        self.update_task_status(subdomain,"Started")
        url = re.sub(r'^https?://', '', url)
        url = url.rstrip('/')
        report_id=task.payload_persistent["report_id"]    
        subdomain = re.sub(r'^https?://', '', subdomain)
        subdomain = subdomain.rstrip('/')    
        self.subdomain=subdomain
        try:
            
            result,resultarr=self.scan(url,source)
            self.waitformongo()
            db=self.db
            collection=db["reports"]
            if result !=[]:
                collection.update_one({"_id": ObjectId(report_id)}, {"$push": {f"Vulns.dalfox": {"$each": result}}})
                output = "\n".join(resultarr)
                self.send_discord_webhook(f"New DalFox Vulnerability Found for {url} ",output,channel="main")
            self.update_task_status(subdomain,"Finished")
        except Exception as e:
            self.log.error(e)
            self.update_task_status(subdomain,"Failed")
            raise Exception(e)

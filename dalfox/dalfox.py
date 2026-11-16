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
    def header_args(self,headers):
        """The arguments that give dalfox the session headers.

        Dalfox takes them as ``-H "name: value"`` and sends them with
        every request it makes.
        """
        args=[]
        for name,value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args
    def rundalfox(self,data,headers):
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
            newlinks=self.checklinksexist(self.subdomain, [link for link in p6.stdout.read().decode("utf-8") if is_on_target(self.subdomain, link)])
            if newlinks==[]:
                return [],[]
            # Command 7: dalfox pipe --deep-domxss --multicast --blind 
            # The scan gives every worker a share of its time: the number
            # of workers dalfox starts and the time it may take are
            # bounded, so one target cannot starve the other workers.
            p7 = subprocess.Popen(["dalfox", "pipe", "--deep-domxss", "--multicast","-w",os.getenv("workers_num","50"),"-o",outputfile,"--format","json","--no-color"]+self.header_args(headers), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            p7.stdin.write('\n'.join(newlinks).encode())
            # p7.stdin.close()

            p6.stdout.close()
            try:
                output, _ = p7.communicate(timeout=300)  # 5 minutes timeout
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
                    
    def url_list(self, source, url):
        """The URL list the crawler produced.

        The copy in the object store is temporary: Karton's garbage
        collector removes it once no live task refers to it, so a scanner
        that starts late finds it gone and the scan dies without looking
        at anything.  The database holds the same list, and it is what the
        scanner falls back to.
        """
        try:
            return self.backend.download_object(
                "bhunters",
                f"{source}_" + self.scanid + "_" + self.encode_filename(url),
            )
        except Exception as exc:
            self.log.error(f"the URL list is not in the bucket: {exc}")
            document = self.db["links"].find_one(
                {
                    "report_id": ObjectId(self.report_id),
                    "source": {"$regex": source, "$options": "i"},
                }
            )
            if document is None:
                raise
            links = document.get("Links") or []
            self.log.info(f"using {len(links)} link(s) from the database")
            return "\n".join(str(link) for link in links).encode()

    def checklinksexist(self, subdomain, links):
        """The links of this scanner that this scan has not checked yet.

        The shared base class in the published ``b-hunters`` package keys
        its record by host, and a host can have several scans: the second
        scan of a host reads the first scan's record and skips the URLs it
        has never tested.  The lookup is repeated here until a release of
        the package carries the fix.
        """
        missing_links = []
        if links == "":
            return []
        if isinstance(links, str):
            links = links.splitlines()

        links = [link for link in links if is_on_target(subdomain, link)]
        if not links:
            return []

        self.waitformongo()
        scanid = getattr(self, "scanid", "") or ""
        if not scanid:
            document = self.db["domains"].find_one({"Domain": subdomain})
            if document is None:
                self.log.error("No document found for the specified domain.")
                return []
            scanid = document["Scanid"]

        document = self.db["scans"].find_one({"_id": ObjectId(scanid)})
        if document is None:
            self.log.error(f"No scan document found for the scan id {scanid}.")
            return []
        existing = document.get("ScanLinks", {}).get(self.identity, [])
        missing_links = [link for link in links if link not in existing]
        if missing_links:
            self.db["scans"].update_one(
                {"_id": ObjectId(scanid)},
                {"$push": {f"ScanLinks.{self.identity}": {"$each": missing_links}}},
            )
        return missing_links

    def scan(self,url,source,headers):
        data=self.url_list(source, url)
        result,resultarr=self.rundalfox(data,headers)
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
        self.report_id=report_id
        subdomain = re.sub(r'^https?://', '', subdomain)
        subdomain = subdomain.rstrip('/')    
        self.subdomain=subdomain
        try:
            headers=self.auth_headers(task)
            result,resultarr=self.scan(url,source,headers)
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


def is_on_target(subdomain, link):
    """Is the link part of the target?

    A crawler collects the third-party links of a page as well.  A
    scanner that is handed the raw list probes those hosts instead of the
    target.  The comparison ignores the scheme and the path, and it takes
    the port into account, because the target is named as host:port.
    """
    if not link:
        return False
    target_host, _, target_port = (subdomain or "").partition(":")
    target_host = target_host.lower()

    candidate = str(link).strip()
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    host, _, port = candidate.partition(":")

    if host.lower() != target_host:
        return False
    if target_port and port != target_port:
        return False
    return True

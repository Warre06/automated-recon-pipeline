import logging
import luigi
from luigi.util import inherits
from luigi.contrib.external_program import ExternalProgramTask
from recon.targets import TargetList
from recon.config import top_tcp_ports, top_udp_ports, masscan_config
from collections import defaultdict
from pprint import pprint
import json
import pickle
import subprocess
from recon.amass import ParseAmassOutput

@inherits(TargetList, ParseAmassOutput)
#ExternalProgramTask om masscan uit te voeren via subprocesses
class Masscan(luigi.Task):
    rate = luigi.Parameter(default=masscan_config.get("rate"))
    interface = luigi.Parameter(default=masscan_config.get("iface")) #kali linux standaard interface
    top_ports = luigi.IntParameter(default=0)
    ports = luigi.Parameter(default="")

    def __init__(self, *args, **kwargs):
        super(Masscan,self).__init__(*args,**kwargs)
        self.masscan_output = f"masscan.{self.target_file}.json"

    #Deze functie zorgt ervoor dat de --top-ports of --ports argument juist ingevoerd zijn en niet allebei voorkomen
    def run(self):
        if self.ports and self.top_ports:
            logging.error("Only --ports or --top-ports is permitted, not both")
            #We gebruiken exit() omdat anders None zal teruggegeven worden door ExternalProgramTask's program_args functie en dit zal voor verder verloop van de pipeline alles vermoeilijken
            exit(1)
        if not self.ports and not self.top_ports:
            logging.error("Must specify at least 1, either --top-ports or --ports")
            exit(2)
        if self.top_ports < 0:
            logging.error("--top-ports must be greater than 0")
            exit(3)
        if self.top_ports:
            #als --top-ports gebruikt worden moeten we de top_ports van de config file juist formatteren voor de masscan --ports optie
            top_tcp_ports_str = ",".join(str(x) for x in top_tcp_ports)
            top_udp_ports_str = ",".join(str(x) for x in top_udp_ports)

            self.ports = f"{top_tcp_ports_str},U:{top_udp_ports_str}"
            self.top_ports = 0
        
        #dit stukje is later toegevoegd om de 2 verschillende flows van domains en IP's terug te kunnen linken aan elkaar bij verder verloop, in luigi documentatie noemt dit dynamic dependencies
        target_list = yield TargetList(target_file=self.target_file)

        if target_list.path.endswith("domains"):
            yield ParseAmassOutput(target_file=self.target_file,exempt_list=self.exempt_list)
        #na dat alle parameters goed zijn verwerkt wordt het commando om de masscan scan uit te voeren opgemaakt, let op dat de input file de output file is van de vorige task
        command = ["masscan","-v","--open","--banners","--rate",self.rate,"-e",self.interface,"-oJ",self.masscan_output,"--ports",self.ports,"-iL",target_list.path.replace("domains","ips"),]

        subprocess.run(command)
    
    
    #definieert de output aka target (in luigi taal) van deze task, dit is een json file zoals we hebben aangeduid op lijn 18
    def output(self):
        return luigi.LocalTarget(self.masscan_output)
    
@inherits(Masscan)
class ParseMasscanOutput(luigi.Task):
    
    #Wat zijn de dependencies van deze task ? De vorige, namelijk de masscan zelf, we moeten eerst een output hebben voor we die kunnen parsen
    def requires(self):
        args = {
            "rate":self.rate,
            "target_file": self.target_file,
            "top_ports":self.top_ports,
            "interface":self.interface,
            "ports":self.ports,
        }
        return Masscan(**args)
    
    #output file aka target, alle volgende tasks zullen deze file nodig hebben om hun task uit te voeren
    def output(self):
        return luigi.LocalTarget(f"masscan.{self.target_file}.parsed.pickle")
    
    #de effectieve functie die de logica bevat voor het omzetten van JSON naar een formaat voor verder gebruik (pickled dictionary voor nmap scan)
    def run(self):
        ip_dict = defaultdict(lambda: defaultdict(set))

        try: 
            entries = json.load(self.input().open()) #json resultaten van masscan scan inladen
        except json.decoder.JSONDecodeError as e:
            return print(e)
        
        #dit stukje code is gegenereerd door chatGPT
        for entry in entries:
            single_target_ip = entry.get("ip")
            for port_entry in entry.get("ports"):
                protocol = port_entry.get("proto")
                ip_dict[single_target_ip][protocol].add(str(port_entry.get("port")))
        
        with open(self.output().path,"wb") as f:
            pickle.dump(dict(ip_dict), f)
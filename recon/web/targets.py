import luigi
from luigi.util import inherits
from recon.amass import ParseAmassOutput
from recon.masscan import ParseMasscanOutput
import pickle
from recon.config import web_ports

# er wordt verwacht dat Masscan en Amass al gelopen hebben, hierna zal het de geparsede output van deze scans gebruiken.
@inherits(ParseMasscanOutput, ParseAmassOutput)
class GatherWebTargets(luigi.Task):

    def requires(self):
        args = {
            "rate":self.rate,
            "target_file":self.target_file,
            "top_ports":self.top_ports,
            "interface":self.interface,
            "ports":self.ports,
        }
        return {
            "masscan-output":ParseMasscanOutput(**args),
            "amass-output":ParseAmassOutput(exempt_list=self.exempt_list,target_file=self.target_file),
        }
    
    def output(self):
        return luigi.LocalTarget(f"webtargets.{self.target_file}.txt")
    # deze functie zal alle potentiele web targets verzamelen in 1 bestand om verder te gebruiken in de pipeline
    def run(self):
        targets = set()
        ip_dict = pickle.load(open(self.input().get("masscan-output").path,"rb"))

        for target, protocol_dict in ip_dict.items():
            for protocol, ports in protocol_dict.items():
                for port in ports:
                    if protocol == "udp":
                        continue
                    if port == "80":
                        targets.add(target)
                    elif port in web_ports:
                        target.add(f"{target}:{port}")
        
        for amass_result in self.input().get("amass-output").values():
            with amass_result.open() as f:
                for target in f:
                    targets.add(target.strip())
        
        with self.output().open("w") as f:
            for target in targets:
                f.write(f"{target}\n")
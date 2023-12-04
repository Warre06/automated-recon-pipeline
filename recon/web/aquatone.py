import luigi
from luigi.util import inherits
from recon.web.targets import GatherWebTargets
from recon.config import defaults, tool_paths
from pathlib import Path
import subprocess

#gebruikt het bestand die de targets.py heeft gegenereerd
@inherits(GatherWebTargets)
class AquatoneScan(luigi.Task):
    threads = luigi.Parameter(default=defaults.get("threads",""))
    scan_timeout = luigi.Parameter(default=defaults.get("aquatone-scan-timeout",""))

    #Aquatone depend op GatherWebTargets om te kunnen runnen
    def requires(self):
        args = {
            "rate":self.rate,
            "target_file":self.target_file,
            "top_ports":self.top_ports,
            "interface":self.interface,
            "ports":self.ports,
            "exempt_list":self.exempt_list,

        }
        return GatherWebTargets(**args)
    
    # output van deze task
    def output(self):
        return luigi.LocalTarget(f"aquatone-{self.target_file}-results")

    def run(self):
        Path(self.output().path).mkdir(parents=True,exist_ok=True)

        command = [
            tool_paths.get("aquatone"),
            "-self-timeout",
            self.scan_timeout,
            "-threads",
            self.threads,
            "-silent",
            "out",
            self.output().path,
        ]
        #let op : aangezien we van luigi.Task overerven en niet van ExternalTask zullen we dus onze target list met stdin moeten meegeven ipv een argument
        with self.input().open() as target_list:
            subprocess.run(command, stdin=target_list)
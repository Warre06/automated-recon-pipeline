import luigi
from luigi.util import inherits
from luigi.contrib.external_program import ExternalProgramTask
from recon.config import tool_paths,defaults
from recon.web.targets import GatherWebTargets

@inherits(GatherWebTargets)
class TKOSubsScan(ExternalProgramTask):

    #TKOSubsScan depends on GatherWebTargets to run !!
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
    
    #Geeft de target output terug voor deze task
    def output(self):
        return luigi.LocalTarget(f"tkosubs.{self.target_file}.csv")
    
    def program_args(self):
        command = [
            tool_paths.get("tko-subs"),
            f"-domains={self.input().path}",
            f"-data={tool_paths.get('tko-subs-dir')}/providers-data.csv",
            f"-output={self.output().path}"
        ]
        return command
    

@inherits(GatherWebTargets)
class SubjackScan(ExternalProgramTask):
    threads = luigi.Parameter(default=defaults.get("threads",""))

    #Zoals bij tkosubsclasse is deze task ook afhankelijk van de eerst gevonden webtargets
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
    
    def output(self):
        return luigi.LocalTarget(f"subjack.{self.target_file}.txt")
    
    #definieert opties/argumenten voor de subjackscan
    def program_args(self):
        command = [
            tool_paths.get("subjack"),
            "-w",
            self.input().path,
            "-t",
            self.threads,
            "-a",
            "-timeout",
            "30",
            "-o",
            self.output().path,
            "v",
            "-ssl",
            "-c",
            tool_paths.get("subjack-fingerprints")
        ]
        return command
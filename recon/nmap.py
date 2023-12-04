import luigi
from luigi.util import inherits
import logging
import pickle
import subprocess
from pathlib import Path
import concurrent.futures

from recon.masscan import ParseMasscanOutput

@inherits(ParseMasscanOutput)
class ThreadedNmap(luigi.Task):
    threads = luigi.Parameter(default=10)

    # Het is al wel duidelijk denk ik, de requires() functie geeft weer welke tasks moeten afgerond zijn voordat deze gestart kan worden
    def requires(self):
        args = {
            "rate":self.rate,
            "target_file":self.target_file,
            "top_ports": self.top_ports,
            "interface": self.interface,
            "ports":self.ports,
        }
        return ParseMasscanOutput(**args)
    
    #Bepaalt de target file van deze task aka wat deze task zal genereren na voltooiing
    def output(self):
        return luigi.LocalTarget(f"{self.target_file}-nmap-results")

    # In deze functie zal onze pickled target info dictionary geladen worden en nmap zal een scan uitvoeren op ENKEl de open poorten
    def run(self):
        try:
            self.threads = abs(int(self.threads))
        except TypeError:
            return logging.error("The value supplied to --threads must be a positive integer.")
        
        ip_dict = pickle.load(open(self.input().path, "rb"))

        #Dit is ons nmap commando dat we zullen uitvoeren
        nmap_command = [
            "nmap",
            "--open",
            "PLACEHOLDER-IDX-2" "-n",
            "-sC",
            "-T",
            "4",
            "-sV",
            "-Pn",
            "-p",
            "PLACEHOLDER-IDX-10",
            "-oA",
        ]

        commands = list()

        for target, protocol_dict in ip_dict.items():
            for protocol, ports in protocol_dict.items():
                tmp_cmd = nmap_command[:]
                #Zorgen dat juiste scan uitgevoerd wordt op basis van protocol van open poort
                tmp_cmd[2] = "-sT" if protocol == "tcp" else "sU"

                # argument dat meegegeven moet worden aan de -oA nmap optie, plaatst resultaten in subdir
                tmp_cmd[9] = ports
                tmp_cmd.append(f"{self.output().path}/nmap.{target}-{protocol}")

                tmp_cmd.append(target)

                commands.append(tmp_cmd)

        Path(self.output().path).mkdir(parents=True, exist_ok=True)

        #Implementatie om de scans asynchroon/parallel te doen
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(subprocess.run,commands)


#Volgende functie zal Searchploit scan implementeren
@inherits(ThreadedNmap)
class Searchsploit(luigi.Task):
    def requires(self):
        args = {
            "rate":self.rate,
            "ports":self.ports,
            "threads":self.threads,
            "top_ports":self.top_ports,
            "interface":self.interface,
            "target_file":self.target_file
        }
        return ThreadedNmap(**args)
    
    #onze output/target file
    def output(self):
        return luigi.LocalTarget(f"{self.target_file}-searchsploit-results")
    
    def run(self):
        # we verkrijgen de resultaten van de nmap scan in xml formaat, daarna iteraten we erdoor
        for entry in Path(self.input().path).glob("nmap*.xml"):
            #commando om searchsploit te runnen via subprocesses
            proc = subprocess.run(["searchsploit","--nmap",str(entry)],stderr=subprocess.PIPE)
            # checken of er output is
            if proc.stderr:
                # maakt een folder indien er niet is, equivalent aan mkdir -p
                Path(self.output().path).mkdir(parents=True,exist_ok=True)

                #string formatting: take the target specifier aka het TGT deel van de nmap.TGT-PROTOCOL.xml bestand van vorige task
                target = entry.stem.replace("nmap.","").replace("-tcp","").replace("-udp","")

                #creeren van de output file waar we onze STDERR output naartoe schrijven
                Path(f"{self.output().path}/searchsploit.{target}-{entry.stem[-3:]}.txt").write_bytes(proc.stderr)
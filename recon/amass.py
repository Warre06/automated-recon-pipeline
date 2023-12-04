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
import ipaddress

@inherits(TargetList)
class AmassScan(ExternalProgramTask):
    exempt_list = luigi.Parameter(default="")

    # deze klasse depend op de targetfile, zoals aangegeven in de overerving
    def requires(self):
        return TargetList(self.target_file)

    #de functie die de output aka target van deze klasse zal bepalen
    def output(self):
        return luigi.LocalTarget(f"amass.{self.target_file}.json")

    # returned het commando dat wordt meegegeven aan subprocess in de vorm van een list
    def program_args(self):
        command = [
            "amass",
            "enum",
            "-active",
            "-ip",
            "-brute",
            "-min-for-recursive",
            "3",
            "-df",
            self.input().path, #TargetList is het bestand dat wordt meegegeven aan -df functie in de vorm van self.input().path
            "-json",
            f"amass.{self.target_file}.json"
        ]

        if self.exempt_list:
            command.append("-blf") #blacklisted domains meegeven (domains buiten de scope)
            command.append(self.exempt_list)

        return command
    
@inherits(AmassScan)
class ParseAmassOutput(luigi.Task):
    def requires(self):
        args = {"target_file": self.target_file, "exempt_list":self.exempt_list}
        return AmassScan(**args)

    # onze output functie zal 3 bestanden teruggeven ipv 1 bij vorige klassen
    def output(self):
        return {
            "target-ips": luigi.LocalTarget(f"{self.target_file}.ips"),
            "target_ip6s": luigi.LocalTarget(f"{self.target_file}.ip6s"),
            "target-subdomains": luigi.LocalTarget(f"{self.target_file}.subdomains"),
        }
    
    def run(self):
    # we gebruiken set() omdat deze een collectie is van UNIEKE waarden, indien er een waarde 2 keer voorkomt zal deze dus niet opnieuw in de collectie komen
        unique_ips = set()
        unique_ip6s = set()
        unique_subs = set()

        amass_json = self.input().open()
        ip_file = self.output().get("target-ips").open("w")
        ip6_file = self.output().get("target-ip6s").open("w")
        subdomain_file = self.output().get("target-subdomains").open("w")

        #files & collecties zijn ingeladen en geinitialiseerd, nu kunnen we iteraten over onze json entries en parsen wat we nodig hebben
        with amass_json as aj, ip_file as ip_out, ip6_file as ip6_out, subdomain_file as subdomain_out:
            for line in aj:
                entry = json.loads(line)
                unique_subs.add(entry.get("name"))

                #checken of de "name" een ipv6 of ipv4 bevat en schrijven naar juiste set() collectie
                for address in entry.get("addresses"):
                    ipaddr = address.get("ip")
                    if isinstance(ipaddress.ip_address(ipaddr), ipaddress.IPv4Address):
                        unique_ips.add(ipaddr)
                    elif isinstance(ipaddress.ip_address(ipaddr), ipaddress.IPv6Address):
                        unique_ip6s.add(ipaddr)
                
                #tot slot schrijven we de juiste resultaten naar de bijhoren bestanden
                for ip in unique_ips:
                    print(ip,file=ip_out)
                for sub in unique_subs:
                    print(sub,file=subdomain_out)
                for ip6 in unique_ip6s:
                    print(ip6,file=ip6_out)
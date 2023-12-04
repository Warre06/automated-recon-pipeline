import shutil
import logging
import ipaddress
import luigi

class TargetList(luigi.ExternalTask):
    target_file = luigi.Parameter()

    def output(self):
        try:
            with open(self.target_file) as f:
                first_line = f.readline()
                ipaddress.ip_interface(first_line.strip()) #is het een juist ip/netwerk ? 
        except OSError as e:
            #indien men bestand niet kan openen; log error/ return niks
            return logging.error(f"opening {self.target_file}:{e.strerror}")
        except ValueError as e:
            #exception door ip_interface; er wordt een domain verwacht
            logging.debug(e)
            with_suffix = f"{self.target_file}.domains"
        else:
            #als alles goed is gegaan, ip address gevonden
            with_suffix = f"{self.target_file}.ips"
    
        shutil.copy(self.target_file,with_suffix) #kopieren van bestand met juiste extensie
        return luigi.LocalTarget(with_suffix)
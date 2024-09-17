#!/usr/bin/env python3

import json
import requests
import gzip
import tempfile
import sys
import os
from datetime import datetime
from pprint import pprint


class NVD_Fetcher():
    """
    Class to fetch and parse NVD feeds
    """
    
    def __init__(self):
        # year is provided by the user
        self.year = None
        self.years = None
        
        ### Base location for the NVD data feeds
        # https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
        self.base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/"
        self.base_f_name = "nvdcve-1.1-"
        self.suffix_f_name = ".json.gz"

        self.data = []
    
    def _validate_year(self, year):
        """Function to validate year provided, which must match NVD feeds"""
        non_standard = ['modified', 'recent']
        self.years = list(range(2002, datetime.now().year + 1))
        self.years.extend(non_standard)

    def fetch_feed(self, year):
        self.year = year  # needed for dumping into json as well
        json_db = []
        f_name = f"{self.base_url}{self.base_f_name}{year}{self.suffix_f_name}"
        print(f"Downloading gzip file for: {f_name}")
        # FIXME TODO: uncomment the code below
        resp = requests.get(f_name)
        # save output in a temporary file
        if resp.status_code >= 400:
            print(f"ERROR: failed to fetch {f_name} with status code {resp.status_code} and reason {resp.reason}")
            return json_db
        # otherwise, parse the returned data
        data = self.get_nvd_json(resp.content)
        """
        with gzip.open("/Users/amaltar2/Downloads/nvdcve-1.1-2022.json.gz", 'rb') as f:
            file_content = f.read()
            data = json.loads(file_content)
        """
        # FIXME TODO: remove these 3 lines above

        print(f"  Found a total of {data['CVE_data_numberOfCVEs']} CVEs")
        ### Now parse each entry and keep only relevant information
        self.data = []
        for entry in data['CVE_Items']:
            filter_entry = self.parse_cve_entry(entry)
            if filter_entry:
                self.data.append(filter_entry)
        return self.data

    def get_data(self):
        """Returns whatever is in the cache of this object"""
        return self.data

    def get_nvd_json(self, bin_content):
        """
        Function to return JSON content out of a nvd compressed file
        :param bin_content: binary data from the compressed nvd gzip file
        :return: python dictionary with the full NVD file content.
        """
        with tempfile.TemporaryFile() as temp:
            temp.write(bin_content)
            # reset the file handler to the beginning of file
            temp.seek(0)
            with gzip.open(temp, 'rb') as f:
                file_content = f.read()
                return json.loads(file_content)

    def parse_cve_entry(self, entry):
        """
        Given a CVE entry from the NVD dump, parse it and return only the desired fields
        :param entry: dict with full data for a given CVE
        :return: a dict only with curated data, in the format of:
        {"cve_id": string,
        "types": list of strings,
        "description": string,
        }
        """
        cve_data = {"cve_id": "",               # Common Vulnerabilities and Exposures (CVE) ID
                    "types": [],                # Common Weakness Enumeration (CWE) IDs
                    "description": "",          # CVE Description
                    "severity": "",             # CVE severity
                    "score": -1,                # CVE score
                    "publish_date": "",         # CVE publish date
                    "last_modified_date": "",   # CVE last modified date
                    "cpes": []}                 # Common Platform Enumeration (CPE)
        
        cve_data['cve_id'] = entry['cve']['CVE_data_meta']['ID']
        
        for item in entry['cve']['problemtype']['problemtype_data']:
            for item_data in item['description']:
                cve_data['types'].append(item_data['value'])
        
        for item in entry['cve']['description']['description_data']:
            cve_data['description'] += " " + item['value']

        if "DO NOT USE THIS CANDIDATE NUMBER" in cve_data['description']:
            #print(f"DEBUG: {cve_data['cve_id']} is not meant to be used, dropping it.")
            return {}
        if not entry['impact'] and 'Rejected reason:' in cve_data['description']:
            #print(f"DEBUG: {cve_data['cve_id']} has been rejected, dropping it.")
            return {}
            

        if entry['impact']:
            if 'baseMetricV3' in entry['impact']:
                cve_data['severity'] = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                cve_data['score'] = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
            elif 'baseMetricV2' in entry['impact']:
                cve_data['severity'] = entry['impact']['baseMetricV2']['severity']
                cve_data['score'] = entry['impact']['baseMetricV2']['cvssV2']['baseScore']

        cve_data['publish_date'] = entry['publishedDate']
        cve_data['last_modified_date'] = entry['lastModifiedDate']
        
        cve_data['cpes'] = self.parse_cpe_entry(entry['configurations'])
        return cve_data

    def parse_cpe_entry(self, entry):
        """
        Given the CPE section of a CVE entry from the NVD dump, parse it and return only the desired fields
        :param entry: dict with the CPE data (CVE 'configurations' section)
        :return: a list of dictionary with CPE data, in the format of:
        [{"cpe_match": string,
            "version_start": strings,
            "version_end_inc": string,
            "version_end_exc": string}, ...]
        """
        # NOTE: it would be great if NVD had a static data structure for these CPEs!!!
        cpe_data = []
        for node in entry['nodes']:
            for match in node['cpe_match']:
                if match['vulnerable'] is False:
                    continue
                cpe_dict = {}
                try:
                    cpe_dict['cpe_match'] = match['cpe23Uri']
                    cpe_dict['version_start'] = match.get('versionStartIncluding')
                    cpe_dict['version_end_inc'] = match.get('versionEndIncluding')
                    cpe_dict['version_end_exc'] = match.get('versionEndExcluding')
                    cpe_data.append(cpe_dict)
                except KeyError as exc:
                    print(f"Exception: {str(exc)}. Node entry: {match}")
            # it has a weird structure, where CPEs can have children...
            for child in node['children']:
                # bad coding!!! copy and paste logic above
                for match in child['cpe_match']:
                    if match['vulnerable'] is False:
                        continue
                    cpe_dict = {}
                    try:
                        cpe_dict['cpe_match'] = match['cpe23Uri']
                        cpe_dict['version_start'] = match.get('versionStartIncluding')
                        cpe_dict['version_end_inc'] = match.get('versionEndIncluding')
                        cpe_dict['version_end_exc'] = match.get('versionEndExcluding')
                        cpe_data.append(cpe_dict)
                    except KeyError as exc:
                        pass
                        #print(f"Exception: {str(exc)}. Children entry: {match}")
        return cpe_data
    
    def save_output(self):
        """
        Creates a directory at the current directory and save the parsed CVE
        data for the whole feed file.
        """
        if self.year is None or not self.data:
            print("ERROR: you need to first call fetch_feed(year)")
            return

        # Create directory to store these JSON dumps under the current directory
        dir_name = os.path.join(os.getenv("PWD"), "nvd_filtered_data")
        try:
            os.mkdir(dir_name)
        except FileExistsError as exc:
            print(f"DEBUG: Directory already exists: {dir_name}")
            pass
        
        f_name = os.path.join(dir_name, f"{self.year}.json")
        print(f"Saving CVE parsing as: {f_name}")
        with open(f_name, "wt") as jo:
            json.dump(self.data, jo, indent=2, sort_keys=True)

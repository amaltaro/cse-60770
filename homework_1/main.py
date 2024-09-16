#!/usr/bin/env python3

import json
import sys
import os
from NVD_Fetcher import NVD_Fetcher
from NVD_DB import NVD_DB
from datetime import datetime


def main():
    """
    Executes the whole log of fetching NVD feeds, populating databases,
    investigating dependencies and reporting on vulnerabilities.
    """
    ### input validation
    if len(sys.argv) != 3:
        print("ERROR: Script incorrectly executed. You must provide 2 arguments:")
        print("    mode: values accepted are either 'detectOnly' or 'doAll'")
        print("    input file: path to the pom.xml file")
        print("\n    Example: python3 main.py detectOnly /Users/fulano/pom.xml")
        sys.exit(1)
    supported_modes = ("detectOnly", "doAll")
    mode = sys.argv[1]
    if mode not in supported_modes:
        print(f"ERROR: mode provided '{mode}' does not match supported modes: {supported_modes}")
        sys.exit(2)
    file_path = sys.argv[2]
    if not os.path.isfile(file_path):
        print(f"ERROR: file '{file_path}' does not seem to exist.")
        sys.exit(3)

    fetcher = NVD_Fetcher()
    fetcher.fetch_feed(2022)
    #fetcher.save_output()
    data = fetcher.get_data()
    
    nvd_db = NVD_DB()
    #nvd_db.drop_tables()
    nvd_db.create_tables()
    nvd_db.populate_tables(data)
    nvd_db.drop_tables()
    nvd_db.disconnect()


if __name__ == '__main__':
    sys.exit(main())
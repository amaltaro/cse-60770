#!/usr/bin/env python3

import json
import sys
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from NVD_Fetcher import NVD_Fetcher
from NVD_DB import NVD_DB


def parse_pom_dependencies(pom_file):
    """
    Class to parse a POM XML file.
    Further details at: https://maven.apache.org/guides/introduction/introduction-to-the-pom.html
    """
    # Parse the XML file
    tree = ET.parse(pom_file)
    root = tree.getroot()

    # Namespace used in the POM file
    namespace = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
    # Find all dependencies in the POM file
    dependencies = root.findall('.//mvn:dependency', namespaces=namespace)

    # Loop through each dependency and extract the artifactId and version
    artifact_list = []
    for dep in dependencies:
        group_id = dep.find('mvn:groupId', namespaces=namespace).text
        artifact_id = dep.find('mvn:artifactId', namespaces=namespace).text
        version = dep.find('mvn:version', namespaces=namespace).text
        artifact_list.append((group_id, artifact_id, version))
    return artifact_list


def do_all(nvd_db):
    """
    Function to clean the existent database, fetch all of the NVD feeds,
    parse the feeds and insert the relevant information into sqlite3.
    :param nvd_db: object instance of the NVD_DB class
    :return: an object to the database
    """
    # connect to the database and recreate the relevant tables
    nvd_db.drop_tables()
    nvd_db.create_tables()

    fetcher = NVD_Fetcher()
    print(f"\nWill start fetching feeds and populating the database")
    #feed_labels = list(range(2002, datetime.now().year + 1)) + ['modified', 'recent']
    feed_labels = list(range(2002, datetime.now().year + 1))
    for feed_label in feed_labels:
        fetcher.fetch_feed(feed_label)
        # fetcher.save_output()
        data = fetcher.get_data()

        # then populate the database
        nvd_db.populate_tables(data)
        # nvd_db.drop_tables()

    # now only update the knowledge base with recent/modified feeds
    for feed_label in ['modified', 'recent']:
        data = fetcher.fetch_feed(feed_label)
        # then update the database
        nvd_db.update_tables(data)

    print("Knowledge base database successfully populated.\n")


def main(mode, pom_path):
    """
    Executes the whole logigc of fetching NVD feeds, populating databases,
    investigating dependencies and reporting on vulnerabilities.
    :param mode: how the script is supposed to be executed ()"detectOnly" or "doAll")
    :param pom_path: absolute path to the POM XML file.
    :return: generates a result.txt file in the current directory
    """
    # get an instance of the database object
    nvd_db = NVD_DB()

    if mode == "doAll":
        # then repopulate the knowledge base database
        do_all(nvd_db)

    # now parse the XML POM file
    dependencies = parse_pom_dependencies(pom_path)
    print("*** DEBUG dependencies")
    for vendor, artifact, version in dependencies:
        print(f'Vendor: {vendor}, Artifact: {artifact}, Version: {version}')



if __name__ == '__main__':
    """
    Validates input provided by the user and call the main function
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
    pom_path = sys.argv[2]
    if not os.path.isfile(pom_path):
        print(f"ERROR: file '{pom_path}' does not seem to exist.")
        sys.exit(3)
    
    # Now, execute the actual vulnerability detection logic
    sys.exit(main(mode, pom_path))
#!/usr/bin/env python3

import json
import sys
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from packaging.version import Version, InvalidVersion
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
        this_version = dep.find('mvn:version', namespaces=namespace).text
        artifact_list.append((group_id, artifact_id, this_version))
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


def check_vulnerability(data_match, vendor, artifact, this_version):
    """
    Performs extra matching between the data returned from the knowledge
    base versus the dependency information

    :param data_match: list of tuples with the following columns from the database:
                       cve_name, severity, cpe_match, version_start, version_end_inc, version_end_exc
    :param vendor: string with the vendor name from pom.xml
    :param artifact: string with the artifact name from pom.xml
    :param this_version: string with the version from pom.xml
    """
    # CPE format is like 'cpe:2.3:a:university_of_washington:pine:4.02:*:*:*:*:*:*:*',
    # where "cpe:2.3:" is always present, then "a" is a random char,
    # then "university_of_washington" is the vendor, and "pine" is the artifact
    report = ""
    for cve, sever, cpe, ver_st, ver_end_inc, ver_end_exc in data_match:
        cpe_vendor = cpe.split(":")[3]
        if vendor not in cpe and cpe_vendor not in vendor:
            continue
        #print(f"    DEBUG: vendor: {vendor} in CPE: {cpe}. Versions: {ver_st}, {ver_end_inc}, {ver_end_exc}")

        # Now the annoying part, compare version strings!!!
        if ver_st is None and ver_end_inc is None and ver_end_exc is None:
            #print(f"There is no version defined for: {cve} {cpe}. Software vulnerable!")
            report += f"Dependency: {artifact}\nVersion(s): {this_version}\n"
            report += f"Vulnerabilities:\n- {cve} ({sever} severity)\n\n"
            continue

        # Pre-parse versions because there are all sorts of formats out there
        dict_ver = convert_version(this_version, ver_st, ver_end_inc, ver_end_exc)

        if ver_st:
            if Version(dict_ver["this_version"]) < Version(dict_ver["ver_start"]):
                #print(f'    Skip cpe as version: {dict_ver["this_version"]} < {dict_ver["ver_start"]} version start')
                continue
            if ver_end_inc and (Version(dict_ver["this_version"]) > Version(dict_ver["ver_end_inc"])):
                #print(f'    Skip cpe as version: {dict_ver["this_version"]} > {dict_ver["ver_end_inc"]} version end including')
                continue
            if ver_end_exc and (Version(dict_ver["this_version"]) >= Version(dict_ver["ver_end_exc"])):
                #print(f'    Skip cpe as version: {dict_ver["this_version"]} >= {dict_ver["ver_end_exc"]} version end excluding')
                continue
        if ver_end_inc and (Version(dict_ver["this_version"]) > Version(dict_ver["ver_end_inc"])):
            #print(f'    Skip cpe as version: {dict_ver["this_version"]} > {dict_ver["ver_end_inc"]} version end including and no version start')
            continue
        if ver_end_exc and (Version(dict_ver["this_version"]) >= Version(dict_ver["ver_end_exc"])):
            #print(f'    Skip cpe as version: {dict_ver["this_version"]} >= {dict_ver["ver_end_exc"]} version end excluding and no version start')
            continue
        # then it is vulnerable
        version_msg = make_version_msg(this_version, ver_st, ver_end_inc, ver_end_exc)
        #print(f"    There is no version defined for: {cve} {cpe}. Software vulnerable!")
        report += f"Dependency: {artifact}\nVersion(s): {version_msg}\n"
        report += f"Vulnerabilities:\n- {cve} ({sever} severity)\n\n"
    return report


def convert_version(this_version, ver_start, ver_end_inc, ver_end_exc):
    """
    Any version that is not compliant with PEP-440 - which can be basically
    anything beyond the Python realm - will fail to be parsed and compared.
    So we need to manually extract important fields of the version string.
    :param this_version: string with the current version of the dependency
    :param ver_start: None or a string with the start version including
    :param ver_end_inc: None or a string with the end version including
    :param ver_end_exc: None or a string with the end version excluding
    :return: dict with the version type and the version to be used for comparison, e.g.:
        {"this_version": "1.2.3", "ver_st": "1.2", ...}
    """
    dict_ver = {}
    for item in [("this_version", this_version), ("ver_start", ver_start),
                 ("ver_end_inc", ver_end_inc), ("ver_end_exc", ver_end_exc)]:
        try:
            if not item[1]:
                dict_ver[item[0]] = item[1]  # likely null
            else:
                dict_ver[item[0]] = str(Version(item[1]))
        except InvalidVersion as exc:
            print(f"ERROR: version type: {item[0]} is unparsable. Details: {str(exc)}")
            # then, manually parse it
            tokens = item[1].split(".")
            for idx in range(min(len(tokens), 3)):
                if tokens[idx].isnumeric() is False:
                    tokens[idx] = "0"
            dict_ver[item[0]] = ".".join(tokens[:3])
    return dict_ver


def make_version_msg(this_version, ver_start, ver_end_inc, ver_end_exc):
    """
    Given 4 potential version values, build a message with the correct
    information and comparison operators
    :param this_version: string with the current version of the dependency
    :param ver_start: None or a string with the start version including
    :param ver_end_inc: None or a string with the end version including
    :param ver_end_exc: None or a string with the end version excluding
    """
    msg = ""
    if ver_start:
        msg += f">= {ver_start}"
    if ver_end_inc:
        msg += f"<= {ver_end_inc}"
    if ver_end_exc:
        msg += f"< {ver_end_exc}"
    if not msg:
        # then there is no version information, simply give the current version is vulnerable
        msg = this_version
    return msg


def main(mode, pom_path):
    """
    Executes the whole logic of fetching NVD feeds, populating databases,
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

    # now parse the XML POM file and match the vulnerabilities
    dependencies = parse_pom_dependencies(pom_path)
    #print("*** DEBUG dependencies")
    result = ""
    for vendor, artifact, this_version in dependencies:
        print(f'Vendor: {vendor}, Artifact: {artifact}, Version: {this_version}')

        data_match = nvd_db.search_cpe(artifact)
        report_str = check_vulnerability(data_match, vendor, artifact, this_version)
        result += report_str

    result = "\nKnown security vulnerabilities detected:\n\n" + result
    print(result)
    out_file = os.path.join(os.getenv("PWD"), "result.txt")
    print(f"Saving result of the vulnerability scan at: {out_file}")
    with open(out_file, "wt") as fp:
        fp.write(result)


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
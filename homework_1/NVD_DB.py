#!/usr/bin/env python3

import json
import sys
import os
import sqlite3
from pprint import pprint


class NVD_DB():
    """
    Class to deal with the database
    """
    
    def __init__(self):
        # variable to hold a map of CVE name and row id in the database (CVE name is the key)
        self.cve_map = {}
        self.db_file = os.path.join(os.getenv("HOME"), "nvd_data.db")
        print(f"Initializing database at: {self.db_file}")
        self.connect()

    def connect(self):
        """Open a connection to the database"""
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
        
    def disconnect(self):
        """Close the database connection"""
        self.conn.close()

    def create_tables(self):
        """Create the necessary tables"""
        ### First, a CVE table
        print("Creating table: cve")
        create_sql = """CREATE TABLE IF NOT EXISTS cve (
            cve_name TEXT NOT NULL PRIMARY KEY,
            description TEXT,
            severity TEXT,
            score REAL,
            publish_date TEXT,
            last_modified_date TEXT)"""
        self.cursor.execute(create_sql)
        
        ### Second, a CWE to CVE association table
        print("Creating table: cwe")
        create_sql = """CREATE TABLE IF NOT EXISTS cwe (
            cve_id INTEGER NOT NULL,
            cwe_type TEXT NOT NULL,
            PRIMARY KEY (cve_id, cwe_type)) WITHOUT ROWID"""
        self.cursor.execute(create_sql)

        ### Third, a CPE to CVE association table
        print("Creating table: cpe")
        create_sql = """CREATE TABLE IF NOT EXISTS cpe (
            cve_id INTEGER,
            cpe_match TEXT,
            version_start TEXT,
            version_end_inc TEXT,
            version_end_exc TEXT)"""
#            PRIMARY KEY (cve_id, cpe_match)) WITHOUT ROWID"""
        self.cursor.execute(create_sql)
        
        # Finally, commit these changes
        self.conn.commit()

    def drop_tables(self):
        """It drops all tables in the database"""
        for table_name in ('cpe', 'cwe', 'cve'):
            self.cursor.execute(f"DROP TABLE {table_name}")
        self.conn.commit()

    def populate_tables(self, input_dict):
        """
        Given a dict object with all the data parsed from a NVD feed,
        organize that data and insert everything into the relevant tables.
        :param input_dict: dictionary with well structured CVE data.
        """
        print(f"Parsing a total of {len(input_dict)} CVE entries.")

        insert_data = []
        for entry in input_dict:
            insert_data.append([entry['cve_id'], entry['description'], entry['severity'],
                                entry['score'], entry['publish_date'], entry['last_modified_date']])
        
        print(f"Inserting {len(insert_data)} into the 'cve' table...")
        sql = 'INSERT INTO cve (cve_name, description, severity, score, publish_date, last_modified_date) '
        sql += 'VALUES (?, ?, ?, ?, ?, ?)'
        self.cursor.executemany(sql, insert_data)
        self.conn.commit()
        
        # create the CVE in-memory map
        self._create_cve_map()
        
        self.insert_cwes(input_dict)
        self.insert_cpes(input_dict)
    
    def _create_cve_map(self):
        """
        Based on a 'cve' table already populated, build up a map of CVE name
        and row ID in the table - for easier look up in the code.
        """
        self.cursor.execute('SELECT cve_name, rowid FROM cve')
        self.cve_map = {row[0]:row[1] for row in self.cursor.fetchall()}
        print(f"Created map of {len(self.cve_map)} CVE/RowID pairs")
        
    def insert_cwes(self, input_dict):
        """
        Given a dict object with all the data parsed from a NVD feed,
        organize it and insert the CWE data accordingly.
        :param input_dict: dictionary with well structured CVE data.
        """
        insert_data = []
        for entry in input_dict:
            if not entry['types']:
                continue  # skip it! There are no CWEs defined for this CVE
            key_lookup = entry['cve_id']
            for cwe in entry['types']:
                insert_data.append([self.cve_map[key_lookup], cwe])

        print(f"Inserting {len(insert_data)} into the 'cwe' table...")
        self.cursor.executemany('INSERT INTO cwe (cve_id, cwe_type) VALUES (?, ?)', insert_data)
        self.conn.commit()

    def insert_cpes(self, input_dict):
        """
        Given a dict object with all the data parsed from a NVD feed,
        organize it and insert the CPE data accordingly.
        :param input_dict: dictionary with well structured CVE data.
        """
        insert_data = []
        for entry in input_dict:
            if not entry['cpes']:
                continue  # skip it! There are no CPEs defined for this CVE
            key_lookup = entry['cve_id']
            for cpe in entry['cpes']:
                insert_data.append([self.cve_map[key_lookup], cpe['cpe_match'], cpe['version_start'],
                                    cpe['version_end_inc'], cpe['version_end_exc']])

        print(f"Inserting {len(insert_data)} into the 'cpe' table...")
        sql = 'INSERT INTO cpe (cve_id, cpe_match, version_start, version_end_inc, version_end_exc) '
        sql += 'VALUES (?, ?, ?, ?, ?)'
        self.cursor.executemany(sql, insert_data)
        self.conn.commit()
    


    

#if __name__ == '__main__':
    #fetcher = NVD_Fetcher()
    #data = fetcher.fetch_feed(2012)
    #fetcher.save_output()

import json
import argparse
import sqlite3
import requests
import time
import shutil
import os
import re


def build_filename(name, spec_version, source):
    last_dot = name.rfind('.')
    second_last_dot = name.rfind('.', 0, last_dot)
    if last_dot != -1 and second_last_dot != -1:
        modified_name = name[:second_last_dot] + f"_{source}_" + name[second_last_dot:last_dot]
        modified_name += f".{spec_version}" + name[last_dot:]

    return modified_name

# returns a list of urls to SBOMs stored on S3
def query_database(database, spec, gen_tool):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    sql_command = "SELECT file_url,name,spec_version,source FROM sboms WHERE format = 'json' AND source != 'github' AND spec = 'cdx' AND creator = 'trivy' AND creator_version = '0.39.0' "
    if spec == "" and gen_tool == "":
        args = ()
        sql_command += ";"
    if spec != "" and gen_tool == "":
        args = (spec,)
        sql_command += "AND spec = ?;"
    if spec == "" and gen_tool != "":
        args = (gen_tool,)
        sql_command += "AND creator = ?;"
    if spec != "" and gen_tool != "":
        args = (spec, gen_tool)
        sql_command += "AND spec = ? AND creator = ?;"

    results = []
    try:
        cursor.execute(sql_command, args)
        results = cursor.fetchall()
        conn.commit()
    except sqlite3.Error as e:
        print("SQLite error:", e)
    finally:
        conn.close()

    return results

def download_sboms(benchmark, output):
    try:
        for filename in os.listdir(output):
            file_path = os.path.join(output, filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
    except Exception as e:
        print(f"Failed to clear directory '{output}': {str(e)}")

    i = 1
    for entry in benchmark:
        url = entry[0]
        name = entry[1]
        spec_version = entry[2]
        source = entry[3]

        name = re.sub(r'_(.*)', lambda x: '-' + x.group(1).replace('_', '-'), name)

        print(name)
        print(f"start download {i}")

        result = requests.get(url)
        try:
            result.raise_for_status()
        except Exception as e:
            print(f"Error encountered downloading: {e}")
            continue
        try:
            filename = build_filename(name, spec_version, source)
            parsed_data = json.loads(result.content)
            with open(output + "/" + filename, 'w') as file:
                json.dump(parsed_data, file)
        except Exception as e:
            print(f"Error saving SBOM to file {e}")

        print(f"finish download {url}\n")
        time.sleep(1)
        i += 1


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-d", "--database", dest="database", default="", help="File path to a SQLite3 database")
    parser.add_argument("-s", "--spec", dest="spec", default="", help="SBOM specification to filter by")
    parser.add_argument("-gt", "--gen_tool", dest="gen_tool", default="", help="SBOM generation tool to filter by")
    parser.add_argument("-o", "--output", dest="output", default="", help="Output path")
    parser.add_argument("-h", "--help", dest="help", default="", action="store_true", help="Help")

    args = parser.parse_args()
    database = args.database
    spec = args.spec
    gen_tool = args.gen_tool
    output = args.output
    if args.help != "":
        print(_help)
        exit()

    benchmark = query_database(database, spec, gen_tool)

    download_sboms(benchmark, output)

main()

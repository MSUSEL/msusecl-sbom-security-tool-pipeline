_help = """Python script for running trivy on an SBOM benchmark repoistory.

Command line arguments:
--input (-i): a file path to a folder containing SBOMs in spdx and or cdx in json
--output (-o): path to folder to output SBOMs to. Folder must exist before running this script.

Results are saved in two ways:
1) Simple results: table containing four columns CVE ID,Security Severity,Package,Version
     "[output_name]-[analysis_tool]-SBOM-SIMPLE-RESULTS.csv"
2) Full results: complete dump of data reported
     "[output_name]-[analysis_tool]-SBOM-FULL-RESULTS.json"
"""

import subprocess as sp
import json
import csv
import os
import argparse
import shutil


def generate_simple_results_sarif(file_path):
    with open(file_path) as file:
        try:
            json_data = json.load(file)
        except:
            print(f"Error opening {file}")
            return []
            
    rules = {}
    for rule in json_data.get("runs", [])[0].get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = rule.get("id")
        severity = rule.get("properties", {}).get("security-severity")
        if severity:
            rules[rule_id] = severity
        else:
            rules[rule_id] = 0

    data = []
    for result in json_data.get("runs", [])[0].get("results", []):
        result_id = result.get("ruleId")
        severity = rules[result_id]
        text = result.get("message", {}).get("text")
        package = text.split('\n')[0].split(' ')[1].strip()
        version = text.split('\n')[1].split(' ')[2].strip()
        if result_id and severity:
            data.append([result_id, severity, package, version])

    return data


def run_trivy(sbom_path, output_name, output_path):
    print("start trivy")
    cmd = sbom_path
    trivy_source_res = sp.run(['trivy', 'sbom', '-f', 'sarif', cmd], stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(output_path + output_name + "_trivy-SBOM-FULL-RESULTS.json", "w")
    f.write(trivy_source_res)
    f.close()
    print("finish trivy")
    # ---------------------------------------------------------------------------------------------------- #

def generate_simple_results(output_name, output_path):
    print("start create simple result")
    aggregated_trivy_data = generate_simple_results_sarif(output_path + output_name + "_trivy-SBOM-FULL-RESULTS.json")
    try:
        csv_file = output_path + output_name + "_trivy-SBOM-SIMPLE-RESULTS.csv"
        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['CVE ID', 'Security Severity','Package','Version'])
            writer.writerows(aggregated_trivy_data)
    except Exception as e:
        print("Error generating trivy simple results")
        csv_file = output_path + output_name + "_trivy-SBOM-SIMPLE-RESULTS.csv"
        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['CVE ID', 'Security Severity', 'Package', 'Version'])
            writer.writerow(['ERROR', str(e),0,0])

    print("finish create simple result\n")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument("-h", "--help", dest="help", default="", action="store_true", help="Help")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    if args.help != "":
        print(_help)
        exit()

    if not os.path.exists(_input) or not os.path.isdir(_input):
        print("Path given does not exist or is not a directory")

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
    for filename in os.listdir(_input):
        print(f"{i}: {filename}")
        name_without_extension, _ = os.path.splitext(filename)
        file_path = os.path.join(_input, filename)
        run_trivy(file_path, name_without_extension, output)
        generate_simple_results(name_without_extension, output)
        i += 1


main()

        
        


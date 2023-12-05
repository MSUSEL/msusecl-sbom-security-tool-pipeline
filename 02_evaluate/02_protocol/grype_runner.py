_help = """Python script for running grype on an SBOM benchmark repoistory.

Command line arguments:
--input (-i): a file path to a folder containing SBOMs in spdx and or cdx in json
--output (-o): path to folder to output SBOMs to. Folder must exist before running this script.

Results are saved in two ways:
1) Simple results: table containing two columns CVE ID,Security Severity
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
        json_data = json.load(file)

    rules = {}
    for rule in json_data.get("runs", [])[0].get("tool", {}).get("driver", {}).get("rules", []):
        rule_id = rule.get("id")
        severity = rule.get("properties", {}).get("security-severity")
        package = rule["help"]["text"].split('\n')[2].split(' ')[1].strip()
        version = rule["help"]["text"].split('\n')[3].split(' ')[1].strip()
        if severity:
            rules[rule_id] = (severity, package, version)
        else:
            rules[rule_id] = (0, package, version)

    data = []
    for result in json_data.get("runs", [])[0].get("results", []):
        result_id = result.get("ruleId")
        severity = rules[result_id][0]
        package = rules[result_id][1]
        version = rules[result_id][2]
        if result_id and severity:
            data.append([result_id, severity, package, version])

    return data


def run_grype(sbom_path, output_name, output_path):
    # ---------------------------------------------------------------------------------------------------- #
    print("start grype")
    cmd = "sbom:./" + sbom_path
    grype_source_res = sp.run(['grype', cmd, '-o', 'sarif'], stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(output_path + output_name + "_grype-SBOM-FULL-RESULTS.json", "w")
    f.write(grype_source_res)
    f.close()
    print("finish grype")
    # ---------------------------------------------------------------------------------------------------- #


def generate_simple_results(output_name, output_path):
    print("start create simple result")
    try:
        aggregated_grype_data = generate_simple_results_sarif(output_path + output_name + "_grype-SBOM-FULL-RESULTS.json")
        csv_file = output_path + output_name + "_grype-SBOM-SIMPLE-RESULTS.csv"
        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['CVE ID', 'Security Severity'])
            writer.writerows(aggregated_grype_data)
    except Exception as e:
        print("Error generating grype simple results")
        csv_file = output_path + output_name + "_grype-SBOM-SIMPLE-RESULTS.csv"
        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['CVE ID', 'Security Severity'])
            writer.writerow(['ERROR', str(e)])

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

        run_grype(file_path, name_without_extension, output)
        generate_simple_results(name_without_extension, output)
        i += 1


main()

        
        


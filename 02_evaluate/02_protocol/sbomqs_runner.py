_help = """Python script for running trivy on an SBOM benchmark repoistory.

Command line arguments:
--input (-i): a file path to a folder containing SBOMs in spdx and or cdx in json
--output (-o): path to folder to output SBOMs to. Folder must exist before running this script.

Results are saved:
Complete dump of data reported by each tool
     "[output_name]-[analysis_tool]-SBOM-FULL-RESULTS.json"
"""

import subprocess as sp
import json
import csv
import os
import argparse
import shutil


def run_sbomqs(sbom_path, output_name, output_path):
    print("start sbomqs")
    sbomqs_results = sp.run(['sbomqs', 'score', sbom_path, '--json'], stdout=sp.PIPE, stderr=sp.PIPE).stdout.decode('utf-8')
    f = open(f"{output_path}{output_name}_sbomqs-SBOM-FULL-RESULTS.json", "w")
    f.write(sbomqs_results)
    f.close()
    print("finish sbomqs")

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
        run_sbomqs(file_path, name_without_extension, output)
        i += 1
main()

        
        


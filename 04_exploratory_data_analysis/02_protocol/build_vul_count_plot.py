import json
import matplotlib.pyplot as plt
import argparse
import datetime
import os
import numpy as np

def build_scatter_plot(filename, output, tool, max_c):
    with open(filename, 'r') as json_file:
        vul_data = json.load(json_file)

    print(f"{tool} found: {len(vul_data)} unique vulnerabilities")
    # Extract data for the scatter plot
    occurrences = [data[0] for data in vul_data.values()]
    severity = [float(data[1]) for data in vul_data.values()]
    print(f"{tool} found: {sum(occurrences)} total vulnerabilities")
    low_count = medium_count = high_count = critical_count = 0

    # Count vulnerabilities with different severity levels
    for occ, sev in zip(occurrences, severity):
        if 0.1 <= sev <= 3.9:
            low_count += occ
        elif 4.0 <= sev <= 6.9:
            medium_count += occ
        elif 7.0 <= sev <= 8.9:
            high_count += occ
        elif 9.0 <= sev <= 10.0:
            critical_count += occ

    # Print counts for each severity level
    print(f"Low vulnerabilities: {low_count}")
    print(f"Medium vulnerabilities: {medium_count}")
    print(f"High vulnerabilities: {high_count}")
    print(f"Critical vulnerabilities: {critical_count}")
    
    combined_data = list(zip(occurrences, severity))
    sorted_data = sorted(combined_data, key=lambda item: item[1])
    sorted_occurrences, sorted_severity = zip(*sorted_data)

    # Create a scatter plot
    #plt.figure(figsize=(20, 20))
    plt.scatter(sorted_occurrences, sorted_severity, alpha=0.5)
    plt.title(f'Vulnerability Occurrences vs. Severity (CVSS) - {tool}', fontsize=16)
    plt.xlabel('Occurrences', fontsize=13)
    plt.ylabel('CVSS Score', fontsize=13)
    plt.grid(True)
    plt.xlim(0, max_c)
    #plt.tight_layout()
    d = datetime.datetime.now()
    print("saving figure")
    plt.savefig(output + f'{d.month}-{d.day}-{d.year}-{d.hour}-{d.minute}_vul_count_scatter-{tool}.png')
    plt.clf()

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument("-h", "--help", dest="help", default="", action="store_true", help="Help")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    if not os.path.exists(_input) or not os.path.isdir(_input):
        print("Path given does not exist or is not a directory")

    m = []
    for filename in os.listdir(_input):
        if filename.endswith('.json'):
            with open(_input + filename, 'r') as json_file:
                vul_data = json.load(json_file)

            # Extract data for the scatter plot
            occurrences = [data[0] for data in vul_data.values()]
            m.append(max(occurrences))

    grype_results = ""
    trivy_results = ""
    for filename in os.listdir(_input):
        if filename.endswith('.json'):
            parts = filename.split("_")
            if "grype" in filename:
                grype_results = _input + filename
                tool = "Grype"
            if "trivy" in filename:
                trivy_results = _input + filename
                tool = "Trivy"

            build_scatter_plot(_input + filename, output,tool, max(m) + 10)



main()


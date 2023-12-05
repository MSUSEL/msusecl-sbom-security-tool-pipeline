import os
import argparse
import pandas as pd
import datetime
import csv

def get_most_vulnerable_packages(path, tool):
    files = [os.path.join(path, filename) for filename in os.listdir(path) if
             filename.endswith(".csv") and tool in filename]
    files.sort()

    results = {}
    for i in range(0, len(files)):
        findings = files[i]
        packages = get_unique_packages_and_count_vulnerabilities(findings)
        for key, value in packages.items():
            results[f'{value}-{key}'] = value

    sorted_items = sorted(results.items(), key=lambda item: item[1], reverse=True)

    largest_keys = ['-'.join(item[0].split('-')[1:]) for item in sorted_items[:25]]
    largest_values = [item[1] for item in sorted_items[:25]]

    return largest_keys, largest_values

def get_unique_packages_and_count_vulnerabilities(findings):
    unique_values = {}
    with open(os.path.join(findings), 'r') as file:
        try:
            csv_reader = csv.reader(file)
        except:
            print(f"error loading {findings} skipping\n")
            return {}

        next(csv_reader)
        for row in csv_reader:
            package = row[2]
            version = row[3]
            version = version.split('+')[0]
            pv = f"{package}_{version}"
            if pv in unique_values:
                unique_values[pv] += 1
            else:
                unique_values[pv] = 1
    return unique_values


def main():
    # Create argument parser
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--input", dest="input", default="", help="")
    parser.add_argument("-o", "--output", dest="output", default="", help="")
    parser.add_argument("-h", "--help", dest="help", default="", action="store_true", help="Help")

    args = parser.parse_args()
    _input = args.input + "/"
    output = args.output + "/"

    if not os.path.exists(_input):
        print("Path given does not exist or is not a directory")

    names_trivy, trivy_counts = get_most_vulnerable_packages(_input + "trivy_results/", "trivy")
    names_grype, grype_counts = get_most_vulnerable_packages(_input + "grype_results/", "grype")

    df_grype = pd.DataFrame({'name': names_grype, 'grype_counts': grype_counts})
    df_trivy = pd.DataFrame({'name': names_trivy, 'trivy_counts': trivy_counts})

    d = datetime.datetime.now()
    output_path = output + f"{d.month}-{d.day}-{d.year}-{d.hour}-{d.minute}_sbom_grype_package_vulnerability_counts.csv"
    df_grype.to_csv(output_path, index=False)

    d = datetime.datetime.now()
    output_path = output + f"{d.month}-{d.day}-{d.year}-{d.hour}-{d.minute}_sbom_trivy_package_vulnerability_counts.csv"
    df_trivy.to_csv(output_path, index=False)


main()

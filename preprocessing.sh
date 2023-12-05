#!/bin/bash

command5="python3 03_preprocessing/02_protocol/count_vulnerability_occurrences.py -i 02_evaluate/04_product/grype_results -o 03_preprocessing/04_product"
command6="python3 03_preprocessing/02_protocol/count_vulnerability_occurrences.py -i 02_evaluate/04_product/trivy_results -o 03_preprocessing/04_product"
command7="python3 03_preprocessing/02_protocol/package_vulnerabilities.py -i 02_evaluate/04_product -o 03_preprocessing/04_product"

eval "$command5"
eval "$command6"
eval "$command7"

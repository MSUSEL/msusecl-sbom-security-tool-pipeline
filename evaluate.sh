#!/bin/bash

command2="python3 02_evaluate/02_protocol/grype_runner.py -i 01_acquisition/04_product/SBOMs -o 02_evaluate/04_product/grype_results"
command3="python3 02_evaluate/02_protocol/trivy_runner.py -i 01_acquisition/04_product/SBOMs -o 02_evaluate/04_product/trivy_results"
command4="python3 02_evaluate/02_protocol/sbomqs_runner.py -i 01_acquisition/04_product/SBOMs -o 02_evaluate/04_product/sbomqs_results"

eval "$command2"
eval "$command3"
eval "$command4"

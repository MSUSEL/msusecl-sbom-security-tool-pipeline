#!/bin/bash

command3="python3 04_exploratory_data_analysis/02_protocol/package_vulnerability_distribution.py -i 03_preprocessing/04_product -o 04_exploratory_data_analysis/04_product"
command4="python3 04_exploratory_data_analysis/02_protocol/build_vul_count_plot.py -i 03_preprocessing/04_product -o 04_exploratory_data_analysis/04_product"

eval "$command8"
eval "$command9"


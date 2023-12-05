### Introduction

This data pipeline contains all the code needed to recreate the analyses and
plots contained in our manuscript entitled "Assessing Security Risks of Software 
Supply Chains Using Software Bill of Materials". Each of the folders here is 
intended to be run in sequence. 

All code is written for Python 3.10.12. Regenerating the results has the following system requirements.
Trivy version 0.44.1, Grype version 0.53.1, and Sbomqs 0.0.17 (links found below). Additionally the code relies on the Python libraries: argparse, pandas, os, datetime, csv, subprocess, json, shutil, matplotlib, and numpy.
Finally the database of SBOMs is too large to store on github, thus we store in on google drive (link to download below). The sbomlc.db must be downloaded and placed in 01_acquisition/01_input.  

Python 3.10.12 - [https://www.python.org/downloads/release/python-31012/]

Trivy 0.44.1 - [https://github.com/aquasecurity/trivy/releases/tag/v0.44.1]

Grype 0.53.1 - [https://github.com/anchore/grype/releases/tag/v0.53.1]

Sbomqs 0.0.17 - [https://github.com/interlynk-io/sbomqs]

SBOM database - [https://drive.google.com/file/d/1V7xue_kpAazbJGd7W-RVZGvFkyvXwcCy/view?usp=sharing]


Each folder in the main directory (01_acquisition, 02_evaluate, 
03_preprocessing, and 04_exploratory_data_analysis) contain 4 folders with the same names: 
01_input, 02_protocol, 03_incremental, and 04_product. The 01_input folder has all of the data needed to execute 
the protocol in the 02_protocol folder. The 03_incremental folders hold 
information that was informative, necessary, or both but not essential for 
generating a data product; many of these folders are empty. Each 04_product 
folder contains the data product for each step in the pipeline. Typically the data in the 
04_product folder from the first directory is copied into the 01_acquisition 
folder of the subsequent directory, and so forth, but for stages where the product generated is large ie thousands of SBOMs, we do not copy the product into the next stages
01_input folder, instead we bypass the 01_input and read directly from 04_product from the previous stage. This helps the pipelione save time. 
This happens for 02_evaluate, 03_preprocessing, and 04_exploratory_data_analysis. 

Assuming that an end user has created the proper directory structure, environment, and copied sbomlc.db to 01_acquisition/01_product, they can 
re-run the entire work by executing `./run.sh`. Additionally the user can run each indvidual stage of the pipeline using the following command respectively: 
`./acquisition.sh`, `./evaluate.sh`, `./preprocessing.sh`, and `./explortatory_data-analysis.sh`


### Pipeline folders

#### 01_acquisition
This folder contains the scripts needed to acquire the SBOMs we analyzed. This envolves
querying the SBOM database in 01_acquisition/01_input to extract links to S3 buckets then
using HTTP requests to download each SBOM, finally saving the SBOMs to 01_acquisition/04_product. 

#### 02_evaluate
This folder contains the scripts to evaluate the SBOMs present in 01_acquisition/04_product as well as the results from the static analysis tools used for analysis. This 
includes running Trivy, Grype, and Sbomqs on each SBOM and processing their results. These results are 
outputted as json a full output of each tools findings. Additionally for Trivy and Grype and a simple results is saved
consisting of each vulnerbility found, its CVSS score, the package/version of origin for the SBOM under analysis. 
These results are saved in 02_evaluate/04_product/trivy_results, 02_evaluate/04_product/grype_results, and 02_evaluate/04_product/sbomqs_results respectively.

#### 03_preprocessing
This folder contains the protocol for aggregating the results reported by the selected static analysis tools in the previous stage. 
We build two data frames for each tool output using the aggregated results. The first is a json structured as a dictionary, the keys are each unique vulnerability found across the SBOMs and the corresponding value is a
count of occurences for the vulnerability. The second is a csv file that consists of the top 25 most vulnerable packages found across the SBOMs, along with their version and count of 
occurences.

#### 04_exploratory_data_analysis
This folder uses the dataframes built in the previous stage to build plots allowing us to better understand the data. We build two plots for each tool results. 
First a scatter plot that gives a distribution of CVSS vulnerability scores from static analysis tools. Each blue dot represents a single vulnerability. 
The x-axis shows the CVSS score and the y-axis shows the total number of occurrences found for a given vulnerability. Second we build bar plots using the
top 25 most vulnerable packages collected in the previous stage. All plots found in our manuscript can be regenerated using this pipeline. 


### Funding Agency:  
[<img src="https://www.cisa.gov/profiles/cisad8_gov/themes/custom/gesso/dist/images/backgrounds/6fdaa25709d28dfb5cca.svg" width="20%" height="20%">](https://www.cisa.gov/)

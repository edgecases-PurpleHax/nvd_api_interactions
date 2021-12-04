# NVD API Interaction CLI Tool

## Description

Recently, I was tasked with verifying several CVEs that were discovered in a vulnerability scan, to the tune of 4,000
CVEs. I realized I was going to have to look at the details of these CVEs and that was going to require a lot of manual
searching, which is extremely time-consuming. Originally, this project was just to have something to work with the API,
but I realized with my current task I could make it into something a little more.

## Usage

Currently, there are two options for using the application.

### 1. Using the CLI Tool.

This is my recommended method if you are doing larger amounts of work with CVEs. Simply run cli.py and interact with
prompts. The following menus are available:

1. CVE
   1. Get CVE by ID
      1. Write to file Y/N
         1. Input file name if Y
   2. Get All CVEs
      1. Confirm due to length of time
   3. Get CVE by File
      1. Confirm file is newline seperated
      2. Input file to load
   4. Exit
      1. Exits the CVE menu
2. Formatting
   1. Format Existing NVD Json
      1. Input file to load
   2. Parse Lacework Report
      1. Input file to load
3. Exit
   1. Exits the CLI tool

### 2. As a stand-alone script

<strong>usage: cve.py [-h] [-a] [-i] [-I ID] [-b] [-S START_DATE] [-E END_DATE] [-A] [-f] [-F FILE] [-if INPUT_FILE] [-o OUTPUT] </strong>

A script to interact with the NVD API.

optional arguments:
 -h, --help show this help message and exit
 -a, --all Use this only one time. It will write a file with theentire NVD database
 -i, --get-by-id Requires -I/--ID <CVE ID>. Gets information about CVE ID provided
 -I ID, --ID ID Enter CVE ID in the format CVE-2021-3165.
 -b, --between-dates Requires -S/--Start-Date <Start Date> and -E/--End-Date <End Date>,gets all CVEs between the start and end date
 -S START_DATE, --Start-Date START_DATE (Enter in the format YYYY-MM-DD)
 -E END_DATE, --End-Date END_DATE
 Enter in the format YYYY-MM-DD
 -A, --After-Date Requires -S/--Start-Date <start date>. Gets all CVE from Start date to current date
 -f, --format Requires -F/--File <file name>. Formats an existing json filefrom NVD API
 -F FILE, --File FILE Enter file name to format
 -if INPUT_FILE, --input-file INPUT_FILE
input new line separated file of cve identifiers
 -o OUTPUT, --output OUTPUT

### Installation

For now, the easiest way to install is to follow normal github process

- Git clone https://github.com/rwils83/nvd_api_interactions.git
- pip install -r requirements.txt
  Future minor release will include a proper setup file

## Future Releases

A few notes on future releases:

- Versioning schema: This project will follow a simple schema. \<majorversion\>.\<minorversion\>. I have no intent do
  anything like 1.1.1. It is not that big of a project.
- I am one person, I work 2 jobs, and am in school first time. Releases will occur when they can, I don't want anyone
  to have expectations that won't be met.
- Issues and fixes: Minor version releases will reflect changes related to issues once a fix has been implemented.
- Major Releases: If completely new functionality is added, a major version release will occur. Anything else will be
  covered under minor version release.

## Licensing

Please see License for license information

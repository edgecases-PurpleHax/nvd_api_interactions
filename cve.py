import argparse
import csv
import datetime
import json
import sys
import textwrap
import time
import urllib

import requests

# todo: This should be done with argparse at first. Make it work with CLI then eventually figure out how to make it
#  work with Flask to make a pretty dashboard or some shit.


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"error: {message}\n")
        self.print_help()
        sys.exit()


# Api Interactions
def format_cve_information(cve):
    for test in cve.get("result").get("CVE_Items"):
        try:
            return f"""
{test.get('cve').get('CVE_data_meta').get('ID')} Assigned by: {test.get(
                'cve').get('CVE_data_meta').get('ASSIGNER')} and Published on {datetime.datetime.strptime(test.get(
                'publishedDate'), '%Y-%m-%dT%H:%MZ').strftime("%m/%d/%y")}
______________________________________________________________________
Description: {textwrap.fill(test.get('cve').get('description').get('description_data')[0].get('value'), 60)}
_____________
Attack Vector: {test.get('impact',
                         {'baseMetricV3': {'cvssV3': {'attackVector': 'Not Yet Assigned'}}}).get('baseMetricV3').get(
                'cvssV3').get('attackVector').title()}
_____________
Score: {test.get('impact',
                 {'baseMetricV3': {'cvssV3': {'baseScore': 'Not Yet Assigned'}}}).get('baseMetricV3').get('cvssV3').get(
                'baseScore')}
_____________
Confidentiality Impact: {test.get('impact',
                                  {'baseMetricV3': {'cvssV3': {'confidentialityImpact': 'Not Yet Assigned'}}}).get(
                'baseMetricV3').get('cvssV3').get('confidentialityImpact').title()}
_____________
Integrity Impact: {test.get('impact',
                            {'baseMetricV3': {'cvssV3': {'integrityImpact': 'Not Yet Assigned'}}}).get(
                'baseMetricV3').get('cvssV3').get('integrityImpact').title()}
_____________
Availability Impact: {test.get('impact',
                               {'baseMetricV3': {'cvssV3': {'availabilityImpact': 'Not Yet Assigned'}}}).get(
                'baseMetricV3').get('cvssV3').get('availabilityImpact').title()}
______________________________________________________________________
"""
        except AttributeError as i:
            return f"{test.get('cve').get('CVE_data_meta').get('ID')} has invalid data. Sorry! "
            break


def get_cve_after_date(start_date):
    # todo: Documentation. Get this ready for argparse. Make it pretty.
    r = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/1.0?pubStartDate={start_date}T00:00:00:000 UTC-05:00"
    )
    if r.json()["totalResults"] > 20:
        page = 0
        while page < r.json()["totalResults"]:
            print(
                f"There are {r.json().get('totalResults')} total results. The results will be paginated"
            )
            next_page = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex={page}&pubStartDate={start_date}T00:00:00:000 UTC-05:00"
            )
            if page == 0:
                print(f"This is page #{page + 1}")
            else:
                print(f"This is page #{int(page / 20 + 1)}")
            page = page + 20
            time.sleep(3)
            for cve in next_page.json().get("result").get("CVE_Items"):
                with open(f"Vulnerability_list_since_{start_date}.txt",
                          "a+") as f:
                    f.write(format_cve_information(next_page.json()))
    else:
        return r.json()
    return 0


def load_parsed_data_file(file, output=False, outfile=None):
    if not output:
        with open(file, "r") as f:
            for line in f.readlines():
                # print(line.strip())
                print(get_cve_by_id(line.strip()))
    elif output:
        print(f"Writing to {outfile}. No output will display.")
        with open(file, "r") as f:
            for line in f.readlines():
                with open(outfile, "a") as g:
                    g.write(get_cve_by_id(line.strip()))


def get_cve_between(start_date, end_date):
    params = {
        "pubStartDate": f"{start_date}T00:00:00:000 UTC-05:00",
        "pubEndDate": f"{end_date}T00:00:00:000 UTC-05:00",
    }
    r = requests.get(
        url="https://services.nvd.nist.gov/rest/json/cves/1.0",
        params=urllib.parse.urlencode(params),
    )
    if r.json()["totalResults"] > 20:
        page = 0
        while page < r.json()["totalResults"]:
            if page == 0:
                print(
                    f"There are {r.json().get('totalResults')} total results. The results will be paginated"
                )
            next_page = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex={page}&pubStartDate={start_date}T00:00:00:000 UTC-05:00"
            )
            if page == 0:
                print(f"Writing returned page #{page + 1}")
            else:
                print(f"Writing returned page #{int(page / 20 + 1)}")
            page = page + 20
            time.sleep(3)
            for cve in next_page.json().get("result").get("CVE_Items"):
                with open(
                        f"Vulnerabilities_between_{start_date}_and_{end_date}.txt",
                        "a+") as f:
                    f.write(format_cve_information(next_page.json()))
    else:
        return r.json()
    return 0


def get_cve_by_id(cve_id):
    r = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}")
    return format_cve_information(r.json())


def get_all_cves():
    r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0")
    if r.json()["totalResults"] > 20:
        print(
            f"There are {r.json().get('totalResults')} total results. The results will be paginated, for a total of"
            f" {int(r.json().get('totalResults') / 20 + 1)} pages, which will take around "
            f"{datetime.timedelta(seconds=int((r.json().get('totalResults') / 20 + 1)) * 3)} To finish."
        )
        page = 0
        while page < r.json()["totalResults"]:
            next_page = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex={page}"
            )
            if page == 0:
                print(
                    f"Downloading {page + 1}/{int(r.json().get('totalResults') / 20 + 1)}"
                )
            else:
                print(
                    f"Downloading {int(page / 20 + 1)}/{int(r.json().get('totalResults') / 20 + 1)}"
                )
            page = page + 20
            time.sleep(3)
            for cve in next_page.json().get("result").get("CVE_Items"):
                try:
                    with open(f"Vulnerability_complete.txt", "a+") as f:
                        f.write(format_cve_information(next_page.json()))
                except NameError:
                    with open(f"Vulnerability_complete.txt", "w+") as f:
                        f.write(format_cve_information(next_page.json()))
                except:
                    pass
        else:
            return r.json()
    return 0


# Formatting scripts
def format_existing_json(file):
    to_format = {}
    with open(file, "r") as f:
        to_format.update(json.load(f))
    file = str(file).split(".")[0]
    with open(f"{file}_formatted.txt", "a+") as f:
        f.write(format_cve_information(to_format))
    return f"{file}_formatted.txt"


def lacework_report_parser(report):
    cves = []
    with open(report, "r") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1
                pass
            else:
                if row[0] not in cves:
                    cves.append(row[0])
    report = str(report).split(".")[0]
    with open(f"{report}_report_output_{datetime.date.today()}.txt",
              "w") as file:
        for cve in cves:
            file.write(cve + "\r")
    return f"{report}_report_output_{datetime.date.today()}.txt"


# Argument parsing: Used when CLI tool not run
def parse_args():
    description = "A script to interact with the NVD API."
    parser = MyParser(description=description)
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Use this only one time. It will write a file with the"
        "entire NVD database",
    )
    parser.add_argument(
        "-i",
        "--get-by-id",
        action="store_true",
        help="Requires -I/--ID <CVE ID>. Gets information "
        "about CVE ID provided",
    )
    parser.add_argument("-I",
                        "--ID",
                        action="store",
                        help="Enter CVE ID in the format CVE-2021-3165.")
    parser.add_argument(
        "-b",
        "--between-dates",
        action="store_true",
        help="Requires -S/--Start-Date <Start Date> "
        "and -E/--End-Date <End Date>,gets all "
        "CVEs between the start and end date",
    )
    parser.add_argument("-S",
                        "--Start-Date",
                        action="store",
                        help="Enter in the format YYYY-MM-DD")
    parser.add_argument("-E",
                        "--End-Date",
                        action="store",
                        help="Enter in the format YYYY-MM-DD")
    parser.add_argument(
        "-A",
        "--After-Date",
        action="store_true",
        help="Requires -S/--Start-Date <start date>. Gets"
        " all CVE from Start date to current date",
    )
    parser.add_argument(
        "-f",
        "--format",
        action="store_true",
        help="Requires -F/--File <file name>. Formats an existing json file"
        "from NVD API",
    )
    parser.add_argument("-F",
                        "--File",
                        action="store",
                        help="Enter file name to format")
    parser.add_argument(
        "-if",
        "--input-file",
        action="store",
        help="input new line separated file of cve identifiers",
    )
    parser.add_argument("-o", "--output", action="store")
    args = parser.parse_args(args=None if sys.argv[1:] else ["--help"])
    return args


if __name__ == "__main__":
    args = parse_args()
    if args.all:
        get_all_cves()
    # Get CVE by ID
    if args.get_by_id:
        if not args.ID:
            print("[-] You must enter a CVE ID. Use --help for example.")
            sys.exit()
        else:
            print(get_cve_by_id(args.ID))
    # Get CVE between start and end date
    if args.between_dates:
        if not args.Start_Date and args.End_Date:
            print(
                "[-] You must enter a start date and end date. Enter --help for example."
            )
        else:
            get_cve_between(args.Start_Date, args.End_Date)
    # Get CVEs after Start date
    if args.After_Date:
        if not args.Start_Date:
            print("[-] You must enter a start date. Enter --help for example.")
        else:
            get_cve_after_date(args.Start_Date)
    # Format an existing json file from NVD
    if args.format:
        if not args.File:
            print("[-] You must enter a file name. Enter --help for example.")
        else:
            format_existing_json(args.File)
    if args.input_file:
        if args.output:
            load_parsed_data_file(args.input_file,
                                  output=True,
                                  outfile=args.output)
        else:
            load_parsed_data_file(args.input_file)

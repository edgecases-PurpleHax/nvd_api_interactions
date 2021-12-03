import csv
import sys
cves = []
if len(sys.argv) == 2:
    with open(sys.argv[1], 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1
                pass
            else:
                if row[0] not in cves:
                    cves.append(row[0])

    with open('parsed_data', 'w') as file:
        for cve in cves:
            file.write(cve+"\r")
else:
    print("[-] Usage: python3 report_parser.py <filename>")

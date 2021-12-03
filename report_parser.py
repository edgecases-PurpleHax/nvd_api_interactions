import csv
cves = []
with open('vuln_reports/vuln_report_99941_Dec 03 2021_11_36 (EST).csv', 'r') as csv_file:
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
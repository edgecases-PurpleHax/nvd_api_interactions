import sys

from examples import custom_style_3
from PyInquirer import prompt

import cve


def main_screen():
    menu_prompt = {
        "type": "list",
        "name": "Main Screen",
        "message": "Welcome to NVD Interactions",
        "choices": ["CVE", "Format File", "Exit"],
    }
    answers = prompt(menu_prompt, style=custom_style_3)
    return answers["Main Screen"]


def cve_option():
    menu_prompt = {
        "type": "list",
        "name": "Cve",
        "message": "CVE Main Screen",
        "choices": ["Get by ID", "Get All", "Get from File", "Exit"],
    }
    answers = prompt(menu_prompt, style=custom_style_3)
    if answers["Cve"] == "Get by ID":
        id_prompt = {
            "type": "input",
            "name": "cve_id",
            "message": "Input cve id (Format: CVE-XXXX-XXXX):",
        }
        outfile = [
            {"type": "confirm", "name": "output", "message": "Write to file?"},
            {
                "type": "input",
                "name": "file_name",
                "message": "Enter the filename to write: ",
                "when": lambda answers: answers["output"],
            },
        ]
        cve_id_prompt = prompt(id_prompt)
        cve_id = cve_id_prompt.get("cve_id")
        write_file = prompt(outfile)
        if write_file["output"]:
            print(f"will write file{write_file.get('file_name')}")
        print(cve.get_cve_by_id(cve_id))
    if answers["Cve"] == "Get All":
        sub_menu = [
            {
                "type": "confirm",
                "name": "getallconfirm",
                "message": "Warning. This process may (will) take a long time. You may want to get a drink, "
                "take a smoke break, or nap. Seriously. There are over 120,000 CVEs, and there is a 3 "
                "second break between every 20. Continue?",
            }
        ]
        get_all_prompt = prompt(sub_menu, style=custom_style_3)
        if get_all_prompt["getallconfirm"]:
            cve.get_all_cves()
    if answers["Cve"] == "Get from File":
        submenu = [
            {
                "type": "confirm",
                "name": "filewarning",
                "message": "File must be newline seperated at this time. Continue?",
            },
            {
                "type": "input",
                "name": "loadfile",
                "message": "Enter the filename to load: ",
                "when": lambda answers: answers["filewarning"],
            },
            {
                "type": "confirm",
                "name": "writetofile",
                "message": "Write data to file?",
                "when": lambda answers: answers["filewarning"],
            },
            {
                "type": "input",
                "name": "writefilename",
                "message": "Enter filename to save as: ",
                "when": lambda answers: answers["writetofile"],
            },
        ]
        loadfile_prompt = prompt(submenu)
        if loadfile_prompt["loadfile"] and not loadfile_prompt["writetofile"]:
            cve.load_parsed_data_file(loadfile_prompt["loadfile"])
        if loadfile_prompt["loadfile"] and loadfile_prompt["writetofile"]:
            cve.load_parsed_data_file(
                file=loadfile_prompt["loadfile"],
                output=True,
                outfile=loadfile_prompt["writefilename"],
            )
    else:
        print("More To Come")


def formatting_options():
    menu_prompt = {
        "type": "list",
        "name": "Formatting",
        "message": "Formatting Main Screen",
        "choices": ["Format existing NVD Json", "Parse Lacework Report", "Exit"],
    }
    answers = prompt(menu_prompt, style=custom_style_3)
    sub_menu = [
        {
            "type": "input",
            "name": "loadfile",
            "message": "Enter the name of the file to load: ",
        }
    ]
    if answers["Formatting"] == "Format existing NVD Json":
        sub_answer = prompt(sub_menu, style=custom_style_3)
        print(f"Writing file: {cve.format_existing_json(sub_answer['loadfile'])}")
    if answers["Formatting"] == "Parse Lacework Report":
        sub_answer = prompt(sub_menu, style=custom_style_3)
        print(f'Writing file: {cve.lacework_report_parser(sub_answer["loadfile"])}')


def main():
    answers = main_screen()
    if answers == "CVE":
        cve_option()
    if answers == "Format File":
        formatting_options()
    if answers == "Exit":
        print("Bye for now")
        sys.exit()


if __name__ == "__main__":
    while True:
        main()

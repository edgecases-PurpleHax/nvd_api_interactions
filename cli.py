import sys
from PyInquirer import prompt

from examples import custom_style_1, custom_style_2, custom_style_3

def main_screen():
    menu_prompt = {
        'type': 'list',
        'name': 'Main Screen',
        'message': 'Welcome to NVD Interactions',
        'choices': ["CVE", "Format File", "Exit"]
    }
    answers = prompt(menu_prompt)
    return answers['Main Screen']


def cve_option():
    menu_prompt = {
        'type': 'list',
        'name':'Cve',
        'message': 'CVE Main Screen',
        'choices': ['Get by ID', 'Get All', 'Get from File', 'Exit']
    }
    answers = prompt(menu_prompt)
    if answers['Cve'] == 'Get by ID':
        from cve import get_cve_by_id
        id_prompt = {
            'type': 'input',
            'name': 'cve_id',
            'message': 'input cve id'
        }
        outfile = [{
            'type': 'confirm',
            'name': 'output',
            'message': 'Write to file?'
        },
            {
                'type': "input",
                'name': 'file_name',
                'message':"Enter the filename to write: ",
                'when': lambda answers: answers['output']
            }]
        cve_id_prompt = prompt(id_prompt)
        cve_id = cve_id_prompt.get('cve_id')
        write_file = prompt(outfile)
        if write_file['output']:
            print(f"will write file{write_file.get('file_name')}")
        print(get_cve_by_id(cve_id))
    else:
        print('More To Come')


def main():
    answers = main_screen()
    if answers == "CVE":
        cve_option()
    if answers == "Format File":
        print("More to come")
    if answers == "Exit":
        print("Bye for now")
        sys.exit()


if __name__ == "__main__":
    while True:
        main()
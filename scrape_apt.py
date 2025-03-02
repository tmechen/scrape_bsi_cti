import json
import requests
from bs4 import BeautifulSoup, element

BSI = "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage"
CTI = "/Analysen-und-Prognosen/Threat-Intelligence"
GROUPS_PAGE = "/Aktive_APT-Gruppen/aktive-apt-gruppen_node.html"

def write_to_file(out_data):
    with open("groups_apt.json", 'w+', encoding="utf-8") as f:
        json.dump(out_data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')

def parse_table(table: element):
    headers = []
    for header in table.find('thead').find_all('th'):
        headers.append(header.text.replace('\n', ''))
    groups_data = []
    for row in table.find('tbody').find_all('tr'):
        group_cells = []
        for cell in row.find_all('td'):
            if "\n" in cell.text.strip():
                group_cells.append(cell.text.replace('\n', '(').strip() + ")")
            else:
                group_cells.append(cell.text.strip())
        groups_data.append({headers[i]: cell for i, cell in enumerate(group_cells)})
    return groups_data

def get_table_data(html_response):
    soup = BeautifulSoup(html_response, "html.parser")
    groups_table = soup.find_all("table", {"class": "alternativ2"})[0]
    return parse_table(table=groups_table)

def main():
    url = BSI + CTI + GROUPS_PAGE
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'accept': '*/*'
        }
    response = requests.get(url, headers=headers, timeout=10)
    return get_table_data(html_response=response.text)

if __name__ == "__main__":
    new_data = main()
    write_to_file(new_data)

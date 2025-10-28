import json
import re
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup, element


BSI = "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage"
CTI = "/Analysen-und-Prognosen/Threat-Intelligence"
GROUPS_PAGE = "/Aktive-Crime-Gruppen/aktive-crime-gruppen_node.html"


def create_session():
    """Create a requests session with retry strategy and browser-like headers."""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Browser-like headers
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0'
    })
    
    return session


def clean_text(text):
    """Clean and normalize text content."""
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text


def parse_aliases(name_text):
    """Parse group name and aliases into structured format."""
    name_text = clean_text(name_text)
    
    # Handle "N/A" case
    if name_text.upper() == "N/A":
        return {"name": "N/A", "aliases": []}
    
    # Split on "aka" pattern
    if " (aka " in name_text or "(aka" in name_text:
        match = re.match(r'([^(]+)\s*\(aka\s+([^)]+)\)', name_text)
        if match:
            primary = match.group(1).strip()
            aliases_str = match.group(2).strip()
            aliases = [a.strip() for a in aliases_str.split(',')]
            return {"name": primary, "aliases": aliases}
    
    # Fallback: split on comma if no aka pattern
    parts = [p.strip() for p in name_text.split(',')]
    return {
        "name": parts[0] if parts else "Unknown",
        "aliases": parts[1:] if len(parts) > 1 else []
    }


def split_description(desc_text):
    """Split description into structured bullet points."""
    if not desc_text:
        return []
    
    # Split on sentence endings followed by capital letter
    sentences = re.split(r'(?<=[.!])\s+(?=[A-ZÄÖÜ])', desc_text)
    return [s.strip() for s in sentences if s.strip()]


def parse_characteristics(char_text):
    """Parse characteristics field into structured data."""
    if not char_text:
        return {
            "responsible_for": [],
            "leak_site": False,
            "additional_info": []
        }
    
    responsible_for = []
    leak_site = False
    additional_info = []
    
    # Check for leak site
    if "Leak-Seite bekannt" in char_text or "Leak-Seiten" in char_text:
        leak_site = True
        char_text = re.sub(r'Leak-Seite[n]?\s+bekannt\.?\s*', ' ', char_text)
    
    # Split text into lines by sentence or "Verantwortlich für" pattern
    lines = []
    current_line = ""
    
    # Look for "Verantwortlich für" markers
    verantwortlich_pattern = r'Verantwortlich für '
    parts = re.split(f'({verantwortlich_pattern})', char_text)
    
    i = 0
    while i < len(parts):
        if parts[i].strip() == 'Verantwortlich für':
            if i + 1 < len(parts):
                # Get the next part which contains what they're responsible for
                responsible_text = parts[i + 1].split('.')[0].strip()
                responsible_for.append(responsible_text)
                i += 2
                continue
        else:
            # Split remaining text into sentences
            sentences = re.split(r'(?<=[.!])\s+(?=[A-ZÄÖÜ])', parts[i])
            for sent in sentences:
                sent = sent.strip()
                if sent and not sent.startswith('Verantwortlich'):
                    additional_info.append(sent)
        i += 1
    
    # If no "Verantwortlich für" was found, treat whole text as additional info
    if not responsible_for and not additional_info:
        sentences = re.split(r'(?<=[.!])\s+(?=[A-ZÄÖÜ])', char_text)
        additional_info = [s.strip() for s in sentences if s.strip()]
    
    return {
        "responsible_for": responsible_for,
        "leak_site": leak_site,
        "additional_info": additional_info
    }


def parse_table(table: element):
    """Parse HTML table and extract crime group data."""
    headers = []
    for header in table.find('thead').find_all('th'):
        headers.append(clean_text(header.text))
    
    groups_data = []
    for row in table.find('tbody').find_all('tr'):
        group_cells = []
        for cell in row.find_all('td'):
            group_cells.append(clean_text(cell.text))
        
        # Create structured data
        raw_data = {headers[i]: cell for i, cell in enumerate(group_cells)}
        
        # Transform into cleaner structure
        group_info = parse_aliases(raw_data.get("Gruppenname", raw_data.get("Gruppenname ", "")))
        description = split_description(raw_data.get("Beschreibung", ""))
        characteristics = parse_characteristics(raw_data.get("Besondere Eigenschaften", ""))
        
        structured_group = {
            "group_name": group_info["name"],
            "aliases": group_info["aliases"],
            "description": description,
            "responsible_for": characteristics["responsible_for"],
            "has_leak_site": characteristics["leak_site"],
            "additional_characteristics": characteristics["additional_info"],
            }
        groups_data.append(structured_group)
    
    return groups_data


def get_table_data(html_response):
    """Extract table from HTML response."""
    soup = BeautifulSoup(html_response, "html.parser")
    tables = soup.find_all("table", {"class": "alternativ2"})
    
    if not tables:
        raise ValueError("No table with class 'alternativ2' found")
    
    return parse_table(table=tables[0])


def write_to_file(out_data):
    """Write data to JSON file with pretty formatting."""
    with open("groups_crime.json", 'w', encoding="utf-8") as f:
        json.dump(out_data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(f"Successfully wrote {len(out_data)} crime groups to groups_crime.json")


def main():
    """Main execution function."""
    url = BSI + CTI + GROUPS_PAGE
    
    print(f"Attempting to fetch: {url}")
    
    # Add initial delay
    time.sleep(1)
    
    try:
        session = create_session()
        
        # Manual retry loop
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                print(f"Attempt {attempt + 1}/{max_attempts}...")
                response = session.get(url, timeout=30)
                response.raise_for_status()
                
                print(f"Success! Status code: {response.status_code}")
                return get_table_data(html_response=response.text)
                
            except (requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout) as e:
                if attempt < max_attempts - 1:
                    wait_time = (2 ** attempt) * 2
                    print(f"Connection error: {e}")
                    print(f"Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                else:
                    raise
                    
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        print("\nTroubleshooting tips:")
        print("1. Check if BSI website is accessible in your browser")
        print("2. Try using a VPN if your IP might be blocked")
        print("3. Check corporate firewall/proxy settings")
        print("4. Verify the URL hasn't changed")
        return []
    except (IndexError, ValueError) as e:
        print(f"Error parsing table: {e}")
        return []


if __name__ == "__main__":
    new_data = main()
    if new_data:
        write_to_file(new_data)
    else:
        print("\nNo data retrieved. Please check the error messages above.")

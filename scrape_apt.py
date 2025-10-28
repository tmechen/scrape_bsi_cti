import json
import re
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup, element


BSI = "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage"
CTI = "/Analysen-und-Prognosen/Threat-Intelligence"
GROUPS_PAGE = "/Aktive_APT-Gruppen/aktive-apt-gruppen_node.html"


def create_session():
    """Create a requests session with retry strategy and browser-like headers."""
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=5,  # Total number of retries
        backoff_factor=2,  # Exponential backoff: 2, 4, 8, 16, 32 seconds
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
        allowed_methods=["GET", "POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # More complete browser-like headers
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


def split_sectors(sector_text):
    """Split concatenated sector names into a list."""
    if not sector_text or sector_text.lower() in ["unbekannt", "diverse", ""]:
        return [sector_text] if sector_text else ["unbekannt"]
    
    patterns = [
        r'(Ordnung)(?=[A-ZÄÖÜ])',
        r'(Verwaltung)(?=[A-ZÄÖÜ])',
        r'(Vereinigungen)(?=[A-ZÄÖÜ])',
        r'(Informationstechnologie)(?=[A-ZÄÖÜ])',
        r'(Luftfahrt)(?=[A-ZÄÖÜ])',
        r'(Kunstwissenschaften)(?=[A-ZÄÖÜ])',
        r'(Unterricht)(?=[A-ZÄÖÜ])',
        r'(Rechtsberatung)(?=[A-ZÄÖÜ])',
        r'(Tätigkeiten)(?=[A-ZÄÖÜ])',
        r'(Munition)(?=[A-ZÄÖÜ])',
        r'(Raumfahrzeugbau)(?=[A-ZÄÖÜ])',
        r'(Schifffahrt)(?=[A-ZÄÖÜ])',
        r'(Wirtschaftsaufsicht)(?=[A-ZÄÖÜ])',
    ]
    
    for pattern in patterns:
        sector_text = re.sub(pattern, r'\1|', sector_text)
    
    sectors = [s.strip() for s in sector_text.split('|') if s.strip()]
    return sectors if sectors else [sector_text]


def split_properties(prop_text):
    """Split concatenated properties into bullet points."""
    if not prop_text:
        return []
    
    # Mark CVE patterns to avoid splitting them
    prop_text = re.sub(r'(CVE-\d{4}-\d{4,6}\s*\([^)]+\))(?=[A-Z])', r'\1|||', prop_text)
    
    # Handle "Server " followed by capital letter
    prop_text = re.sub(r'(Server\s+)(?=[A-Z])', r'\1|||', prop_text)
    
    # Split on our marker
    properties = [p.strip() for p in prop_text.split('|||') if p.strip()]
    
    # Clean up any remaining artifacts
    cleaned = [p for p in properties if p and p not in ['.', 'B.', 'z.']]
    
    return cleaned if cleaned else []


def parse_aliases(name_text):
    """Parse group name and aliases into structured format."""
    name_text = clean_text(name_text)
    parts = [p.strip() for p in name_text.split('/')]
    
    if not parts:
        return {"name": "Unknown", "aliases": []}
    
    return {
        "name": parts[0],
        "aliases": parts[1:] if len(parts) > 1 else []
    }


def parse_table(table: element):
    """Parse HTML table and extract APT group data."""
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
        group_info = parse_aliases(raw_data.get("Gruppenname und Aliase", ""))
        sectors = split_sectors(raw_data.get("Wirtschaftszweig in Deutschland nach WZ 2008", ""))
        properties = split_properties(raw_data.get("Besondere Eigenschaften", ""))
        
        structured_group = {
            "group_name": group_info["name"],
            "aliases": group_info["aliases"],
            "targeted_sectors": sectors,
            "characteristics": properties if properties else ["No specific characteristics listed"]
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
    with open("groups_apt.json", 'w', encoding="utf-8") as f:
        json.dump(out_data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(f"Successfully wrote {len(out_data)} APT groups to groups_apt.json")


def main():
    """Main execution function."""
    url = BSI + CTI + GROUPS_PAGE
    
    print(f"Attempting to fetch: {url}")
    
    # Add initial delay to avoid immediate rate limiting
    time.sleep(1)
    
    try:
        session = create_session()
        
        # Manual retry loop with exponential backoff for connection errors
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
                    wait_time = (2 ** attempt) * 2  # 2, 4, 8 seconds
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

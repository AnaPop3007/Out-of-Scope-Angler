import csv
import re
from fuzzywuzzy import fuzz
import requests
import math
import socket
import ssl
from datetime import datetime
from bs4 import BeautifulSoup

# --- PASUL 1: Definește variabilele de risc ---
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'password', 'banking', 
    'update', 'signin', 'confirm', 'support'
]

# Lista cu TLD-uri (extensii) de mare risc
HIGH_RISK_TLDS = {
    '.xyz', '.top', '.loan', '.club', '.stream', '.gq', '.tk', '.ml', '.ga', '.cf',
    '.work', '.online', '.site', '.website', '.click', '.link', '.live', '.space',
    '.buzz', '.men', '.icu', '.fit', '.vip', '.monster'
}

# Header pentru a simula un browser real
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# --- PASUL 2: Funcția de încărcare a listei din CSV ---
def load_top_domains(file_name='top-1m.csv', count=50000):
    """Încarcă primele 'count' domenii din fișierul Tranco CSV."""
    domains = set()
    try:
        with open(file_name, mode='r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:
                    domains.add(row[1]) # Adaugă domeniul (e pe a doua coloană)
                if len(domains) >= count:
                    break
        print(f"--- Am încărcat {len(domains)} domenii populare în memorie. ---")
        return domains
    except FileNotFoundError:
        print(f"!!! EROARE: Nu gasesc fisierul {file_name}. !!!")
        print("--- Rulează 'python update_list.py' pentru a-l descărca. ---")
        print("--- Folosesc o lista de baza locala. ---")
        return {'google.com', 'facebook.com', 'banca-mea.ro'} # Fallback
    except Exception as e:
        print(f"Eroare la citirea CSV: {e}")
        return {'google.com', 'facebook.com'}

# --- PASUL 3: Funcții Ajutătoare (Statice) ---
def calculate_entropy(text):
    """Calculează entropia unui șir de caractere (cât de aleatoriu pare)."""
    if not text:
        return 0
    entropy = 0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    length = len(text)
    if length == 0:
        return 0
        
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy



def get_certificate_age(hostname):
    """
    Verifică vechimea certificatului SSL. 
    Returnează vechimea în zile sau -1 dacă e eroare/http.
    """
    try:
        context = ssl.create_default_context()
       
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Convertim data emiterii în obiect datetime
                issue_date = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                # Calculăm vechimea
                age = (datetime.utcnow() - issue_date).days
                return age
    except Exception:
        # Erori posibile: nu are SSL, timeout, certificat invalid etc.
        return -1 # Semnalăm că nu am putut verifica

def check_for_password_field(url):
    """
    Verifică dacă HTML-ul paginii conține <input type="password">.
    """
    try:
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=3, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Caută toate input-urile de tip "password"
        password_inputs = soup.find_all('input', {'type': 'password'})
        
        return len(password_inputs) > 0
    except Exception:
        # Erori de rețea, timeout, etc.
        return False

# --- PASUL 5: Funcția principală de Risc (v3.1) ---
def get_risk_score(suspicious_url, legitimate_domains):
    """Calculează un scor de risc bazat pe reguli statice ȘI dinamice."""
    
    total_risk_score = 0
    alerts = []
    
    try:
        hostname = re.sub(r'^https?://', '', suspicious_url).split('/')[0].lower()
        clean_url = re.sub(r'^www\.', '', hostname)
    except Exception:
        clean_url, hostname = suspicious_url.lower(), suspicious_url.lower()

    # --- Regulile STATICE (Rapide, bazate pe URL) ---

    # REGULA 1: Similaritate Fuzzy (Typosquatting)
    best_fuzzy_score = 0
    best_match = None
    for legit_url in legitimate_domains:
        score = fuzz.ratio(clean_url, legit_url)
        if score > best_fuzzy_score:
            best_fuzzy_score = score
            best_match = legit_url
    
    is_known_domain = (best_fuzzy_score == 100)

    if best_fuzzy_score > 90 and not is_known_domain:
        total_risk_score += 50
        alerts.append(f"Similaritate mare ({best_fuzzy_score}%) cu {best_match}")

    # REGULA 2 (Actualizată): Cuvinte Cheie Suspecte (Verifică tot URL-ul)
    url_for_keyword_check = suspicious_url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_for_keyword_check:
            total_risk_score += 15
            alerts.append(f"Conține cuvântul suspect: '{keyword}'")

    # REGULA 3: Lungime URL
    if len(clean_url) > 75: 
        total_risk_score += 10
        alerts.append("URL foarte lung (peste 75 caractere)")

    # REGULA 4: Folosire de @
    if '@' in clean_url: 
        total_risk_score += 40
        alerts.append("URL conține '@' (tehnică de ascundere)")

    # REGULA 5: Caractere Non-ASCII (Atac Homoglyph)
    if not clean_url.isascii(): 
        total_risk_score += 50
        alerts.append("Conține caractere non-standard (ex: diacritice, atac homoglyph)")
        
    # REGULA 6: TLD de Risc Înalt
    tld = '.' + clean_url.split('.')[-1]
    if tld in HIGH_RISK_TLDS:
        total_risk_score += 35
        alerts.append(f"Folosește un TLD de mare risc: '{tld}'")
        
    # REGULA 7: Prea multe cratime sau puncte (Subdomenii)
    if clean_url.count('.') > 4:
         total_risk_score += 20
         alerts.append(f"Prea multe subdomenii (puncte): {clean_url.count('.')}")
    if clean_url.count('-') > 3:
         total_risk_score += 15
         alerts.append(f"Prea multe cratime: {clean_url.count('-')}")

    # REGULA 8: Entropie Ridicată (Pare aleatoriu)
    domain_part = ".".join(clean_url.split('.')[:-1])
    entropy = calculate_entropy(domain_part)
    if entropy > 3.5: # 3.5 e un prag bun pentru nume de domenii
        total_risk_score += 25
        alerts.append(f"Entropie ridicată ({entropy:.2f}), pare generat aleatoriu")
    
    # --- Regulile DINAMICE (Live, pot fi mai lente) ---
    # Le rulăm doar dacă nu este un site cunoscut
    if not is_known_domain:
        
        # REGULA 9: Vechimea Certificatului SSL
        cert_age_days = get_certificate_age(hostname)
        if cert_age_days == -1:
            total_risk_score += 10 # Penalizare mică pentru HTTP sau eroare
            alerts.append("Nu s-a putut verifica certificatul SSL (HTTP sau eroare)")
        elif cert_age_days < 7: # Certificat creat în ultima săptămână!
            total_risk_score += 50
            alerts.append(f"Certificat SSL extrem de nou (creat acum {cert_age_days} zile)")
            
        # REGULA 10 (Actualizată): Pagină conține parolă SAU cale de login
        path_has_login_keyword = any(kw in url_for_keyword_check for kw in ['/login', '/signin', '/auth'])
        
        if check_for_password_field(suspicious_url):
            total_risk_score += 40
            alerts.append("Pagină nouă/necunoscută care cere o parolă (detectat în HTML)")
        elif path_has_login_keyword:
            # Dacă scanarea HTML eșuează (poate e JS),
            # dar calea URL conține '/login', e la fel de suspect
            total_risk_score += 25
            alerts.append(f"Pagină nouă/necunoscută cu o cale URL suspectă de login")

    # --- Status Final ---
    status = 'Safe'
    if total_risk_score >= 90: # Prag mai mare
        status = 'DANGEROUS'
    elif total_risk_score >= 50: # Prag mai mare
        status = 'Suspicious'

    return {
        'url_testat': suspicious_url,
        'risk_score': total_risk_score,
        'status': status,
        'potential_match': best_match if best_fuzzy_score > 90 else 'None',
        'alerts_triggered': alerts
    }

# --- PASUL 6: Blocul de Testare (Actualizat) ---
if __name__ == "__main__":
    
    # Încarcă lista de domenii o singură dată la început
    LEGITIMATE_URLS = load_top_domains()
    
    if LEGITIMATE_URLS:
        print("\n--- Rularea testelor pentru Motorul de Risc v3.1 (Reparat) ---")
        
        # Test 1: Impostor (Fuzzy + Cuvinte Cheie)
        test_1 = "http://login-google.com.security-update.net/verify-account"
        print(f"\nTest 1 (Impostor) ({test_1}):\n {get_risk_score(test_1, LEGITIMATE_URLS)}")
        
        # Test 2: "Denumirea ciudată" (nouă)
        test_2 = "https://www.pltfrm.com/login" # Un site legitim, dar necunoscut
        print(f"\nTest 2 (Site Necunoscut cu Login) ({test_2}):\n {get_risk_score(test_2, LEGITIMATE_URLS)}")

        # Test 3: Site normal (ar trebui să fie 'Safe')
        test_3 = "https://www.google.com"
        print(f"\nTest 3 (Site Sigur) ({test_3}):\n {get_risk_score(test_3, LEGITIMATE_URLS)}")
        
        # Test 4: Atac Homoglyph (cu diacritică)
        test_4 = "bancă-mea.ro"
        print(f"\nTest 4 (Homoglyph) ({test_4}):\n {get_risk_score(test_4, LEGITIMATE_URLS)}")

        # Test 5: Atac cu entropie și TLD de risc
        test_5 = "http://a8sd9as8d9a8sjd9k.xyz/login"
        print(f"\nTest 5 (Entropie + TLD Risc) ({test_5}):\n {get_risk_score(test_5, LEGITIMATE_URLS)}")
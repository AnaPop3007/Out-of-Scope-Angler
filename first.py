import csv
import re
from fuzzywuzzy import fuzz
import requests

# --- PASUL 1: Definește variabilele de risc ---
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'password', 'banking', 
    'update', 'signin', 'confirm', 'support'
]

# --- PASUL 2: Funcția de încărcare a listei din CSV ---
def load_top_domains(file_name='top-1m.csv', count=10000):
    """Încarcă primele 'count' domenii din fișierul Tranco CSV."""
    domains = set() # Folosim un 'set' pentru căutare super-rapidă
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

# --- PASUL 3: Funcția principală de Risc ---
def get_risk_score(suspicious_url, legitimate_domains):
    """Calculează un scor de risc bazat pe mai multe reguli."""
    
    total_risk_score = 0
    alerts = []

    # Curăță URL-ul pentru analiză (scoate http, www etc.)
    try:
        clean_url = re.sub(r'^https?://', '', suspicious_url).split('/')[0].lower()
        clean_url = re.sub(r'^www\.', '', clean_url)
    except Exception:
        clean_url = suspicious_url.lower()

    # --- REGULA 1: Similaritate Fuzzy (Typosquatting) ---
    best_fuzzy_score = 0
    best_match = None
    
    for legit_url in legitimate_domains:
        score = fuzz.ratio(clean_url, legit_url)
        if score > best_fuzzy_score:
            best_fuzzy_score = score
            best_match = legit_url
    
    # Prag agresiv: dacă seamănă FOARTE mult, dar nu e identic
    if best_fuzzy_score > 90 and best_fuzzy_score < 100:
        total_risk_score += 50
        alerts.append(f"Similaritate foarte mare ({best_fuzzy_score}%) cu {best_match}")

    # --- REGULA 2: Cuvinte Cheie Suspecte ---
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in clean_url:
            total_risk_score += 15
            alerts.append(f"Conține cuvântul suspect: '{keyword}'")

    # --- REGULA 3: Lungime URL (Peste 75 caractere) ---
    if len(clean_url) > 75:
        total_risk_score += 10
        alerts.append("URL foarte lung (peste 75 caractere)")

    # --- REGULA 4: Folosire de @ ---
    if '@' in clean_url:
        total_risk_score += 40
        alerts.append("URL conține '@' (tehnică de ascundere)")

    # --- REGULA 5: Caractere Non-ASCII (Atac Homoglyph) ---
    if not clean_url.isascii():
        total_risk_score += 50
        alerts.append("Conține caractere non-standard (ex: diacritice, atac homoglyph)")
         
    # --- Status Final ---
    status = 'Safe'
    if total_risk_score >= 80:
        status = 'DANGEROUS'
    elif total_risk_score >= 40:
        status = 'Suspicious'

    return {
        'url_testat': suspicious_url,
        'risk_score': total_risk_score,
        'status': status,
        'potential_match': best_match if best_fuzzy_score > 90 else 'None',
        'alerts_triggered': alerts
    }

# --- PASUL 4: Blocul de Testare ---
if __name__ == "__main__":
    
    # Încarcă lista de domenii o singură dată la început
    LEGITIMATE_URLS = load_top_domains()
    
    if LEGITIMATE_URLS:
        print("\n--- Rularea testelor pentru Motorul de Risc ---")
        
        # Test 1: Atac Fuzzy + Cuvinte Cheie
        test_1 = "http://login-google.com.security-update.net/verify-account"
        print(f"\nTest 1 ({test_1}):\n {get_risk_score(test_1, LEGITIMATE_URLS)}")
        
        # Test 2: Atac Homoglyph (cu diacritică)
        test_2 = "bancă-mea.ro"
        print(f"\nTest 2 ({test_2}):\n {get_risk_score(test_2, LEGITIMATE_URLS)}")

        # Test 3: URL normal
        test_3 = "https://www.google.com"
        print(f"\nTest 3 ({test_3}):\n {get_risk_score(test_3, LEGITIMATE_URLS)}")

        # Test 4: URL identic (ar trebui să fie safe, scorul fuzzy e 100)
        test_4 = "google.com"
        print(f"\nTest 4 ({test_4}):\n {get_risk_score(test_4, LEGITIMATE_URLS)}")
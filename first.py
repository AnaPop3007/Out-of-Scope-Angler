import csv
import re
from fuzzywuzzy import fuzz
import requests
import math # Avem nevoie de 'math' pentru a calcula entropia

# --- PASUL 1: Definește variabilele de risc ---
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'password', 'banking', 
    'update', 'signin', 'confirm', 'support'
]

# Lista cu TLD-uri (extensii) de mare risc
# Acestea sunt ieftine și folosite masiv în phishing
HIGH_RISK_TLDS = {
    '.xyz', '.top', '.loan', '.club', '.stream', '.gq', '.tk', '.ml', '.ga', '.cf',
    '.work', '.online', '.site', '.website', '.click', '.link', '.live', '.space',
    '.buzz', '.men', '.icu', '.fit', '.vip', '.monster'
}

# --- PASUL 2: Funcția de încărcare a listei din CSV ---
def load_top_domains(file_name='top-1m.csv', count=10000):
    """Încarcă primele 'count' domenii din fișierul Tranco CSV."""
    domains = set()
    try:
        with open(file_name, mode='r', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            for row in csv_reader:
                if row:
                    domains.add(row[1])
                if len(domains) >= count:
                    break
        print(f"--- Am încărcat {len(domains)} domenii populare în memorie. ---")
        return domains
    except FileNotFoundError:
        print(f"!!! EROARE: Nu gasesc fisierul {file_name}. !!!")
        print("--- Rulează 'python update_list.py' pentru a-l descărca. ---")
        print("--- Folosesc o lista de baza locala. ---")
        return {'google.com', 'facebook.com', 'banca-mea.ro'}
    except Exception as e:
        print(f"Eroare la citirea CSV: {e}")
        return {'google.com', 'facebook.com'}

# --- PASUL 3: Funcții Ajutătoare Euristice ---

def calculate_entropy(text):
    """Calculează entropia unui șir de caractere (cât de aleatoriu pare)."""
    if not text:
        return 0
    entropy = 0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    length = len(text)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy

# --- PASUL 4: Funcția principală de Risc ---
def get_risk_score(suspicious_url, legitimate_domains):
    """Calculează un scor de risc bazat pe mai multe reguli."""
    
    total_risk_score = 0
    alerts = []

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
    if best_fuzzy_score > 90 and best_fuzzy_score < 100:
        total_risk_score += 50
        alerts.append(f"Similaritate mare ({best_fuzzy_score}%) cu {best_match}")

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
        
    # --- REGULA 6 (NOUĂ): TLD de Risc Înalt ---
    tld = '.' + clean_url.split('.')[-1]
    if tld in HIGH_RISK_TLDS:
        total_risk_score += 35
        alerts.append(f"Folosește un TLD de mare risc: '{tld}'")
        
    # --- REGULA 7 (NOUĂ): Prea multe cratime sau puncte (Subdomenii) ---
    if clean_url.count('.') > 4:
         total_risk_score += 20
         alerts.append(f"Prea multe subdomenii (puncte): {clean_url.count('.')}")
    if clean_url.count('-') > 3:
         total_risk_score += 15
         alerts.append(f"Prea multe cratime: {clean_url.count('-')}")

    # --- REGULA 8 (NOUĂ): Entropie Ridicată (Pare aleatoriu) ---
    # Analizăm doar partea principală a domeniului, fără TLD
    domain_part = ".".join(clean_url.split('.')[:-1])
    entropy = calculate_entropy(domain_part)
    if entropy > 3.5: # 3.5 e un prag bun pentru nume de domenii
        total_risk_score += 25
        alerts.append(f"Entropie ridicată ({entropy:.2f}), pare generat aleatoriu")

    # --- Status Final (Praguri ajustate) ---
    status = 'Safe'
    if total_risk_score >= 90:
        status = 'DANGEROUS'
    elif total_risk_score >= 50:
        status = 'Suspicious'

    return {
        'url_testat': suspicious_url,
        'risk_score': total_risk_score,
        'status': status,
        'potential_match': best_match if best_fuzzy_score > 90 else 'None',
        'alerts_triggered': alerts
    }

# --- PASUL 5: Blocul de Testare (Actualizat) ---
if __name__ == "__main__":
    
    LEGITIMATE_URLS = load_top_domains()
    
    if LEGITIMATE_URLS:
        print("\n--- Rularea testelor pentru Motorul de Risc v2 ---")
        
        # Test 1: Impostor (Fuzzy + Cuvinte Cheie)
        test_1 = "http://login-google.com.security-update.net/verify-account"
        print(f"\nTest 1 ({test_1}):\n {get_risk_score(test_1, LEGITIMATE_URLS)}")
        
        # Test 2: Atac Homoglyph (cu diacritică)
        test_2 = "bancă-mea.ro"
        print(f"\nTest 2 ({test_2}):\n {get_risk_score(test_2, LEGITIMATE_URLS)}")

        # Test 3: URL normal (ar trebui să fie 'Safe')
        test_3 = "https://www.google.com"
        print(f"\nTest 3 ({test_3}):\n {get_risk_score(test_3, LEGITIMATE_URLS)}")

        # Test 4: "Denumirea ciudată" (nouă)
        test_4 = "http://secure-client-portal-x8z.xyz"
        print(f"\nTest 4 (Denumire Ciudată) ({test_4}):\n {get_risk_score(test_4, LEGITIMATE_URLS)}")
        
        # Test 5: Atac cu entropie (nou)
        test_5 = "http://a8sd9as8d9a8sjd9k.online/login"
        print(f"\nTest 5 (Entropie) ({test_5}):\n {get_risk_score(test_5, LEGITIMATE_URLS)}")
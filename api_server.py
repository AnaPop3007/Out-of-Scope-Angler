from flask import Flask, request, jsonify

# --- PASUL 1: Importă "Creierul" din celălalt fișier ---
# Importăm funcția de risc ȘI funcția de încărcare a listei
try:
    from first import get_risk_score, load_top_domains
except ImportError:
    print("EROARE: Nu gasesc fisierul 'first.py'. Asigura-te ca e in acelasi folder.")
    exit()

# --- PASUL 2: Inițierea aplicației Flask ---
app = Flask(__name__)

# --- PASUL 3: Încărcarea Listei de Domenii (Performanță) ---
# Facem asta O SINGURĂ DATĂ, când pornește serverul.
# Astfel, nu citim fișierul de 10.000 de rânduri la fiecare cerere.
print("Se încarcă lista de domenii în memorie...")
try:
    LEGITIMATE_URLS = load_top_domains()
    if not LEGITIMATE_URLS:
        raise Exception("Lista de domenii este goală.")
    print(f"--- Lista cu {len(LEGITIMATE_URLS)} domenii a fost încărcată. Serverul este gata. ---")
except Exception as e:
    print(f"EROARE CRITICĂ la încărcarea listei de domenii: {e}")
    print("Serverul nu poate porni fără lista de domenii.")
    exit()


# --- PASUL 4: Crearea Endpoint-ului API ---
# Aceasta este "adresa" la care se vor conecta ceilalți.
# '/check-phishing' este numele "ușii"
# methods=['POST'] înseamnă că acceptă doar cereri de tip POST
@app.route('/check-phishing', methods=['POST'])
def check_url_endpoint():
    """
    Endpoint-ul principal care primește un URL și returnează analiza de risc.
    """
    
    # 1. Preia datele JSON trimise (de ex: de la Node.js sau extensie)
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({'error': 'Format JSON invalid'}), 400

    # 2. Verifică dacă datele primite sunt corecte
    if not data or 'url' not in data:
        return jsonify({'error': 'Cererea trebuie sa contina un JSON cu cheia "url"'}), 400
        
    url_to_check = data['url']
    
    # 3. Folosește "creierul" tău (funcția importată)
    try:
        # Trimitem URL-ul și lista deja încărcată în memorie
        result = get_risk_score(url_to_check, LEGITIMATE_URLS)
        
        # 4. Trimite rezultatul înapoi ca JSON
        return jsonify(result)
        
    except Exception as e:
        # Prinde orice eroare neașteptată din funcția ta
        print(f"*** EROARE în timpul rulării get_risk_score: {e} ***")
        return jsonify({'error': 'Eroare internă la procesarea URL-ului'}), 500

# --- PASUL 5: Pornirea Serverului ---
if __name__ == '__main__':
    print("=====================================================")
    print(f"Serverul API Phishing pornește pe http://localhost:5000")
    print("Aștept cereri POST la /check-phishing")
    print("=====================================================")
    # debug=True repornește serverul automat când salvezi fișierul
    app.run(debug=True, port=5000)
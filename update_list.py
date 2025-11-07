import requests
import zipfile # Lista vine ca un .zip
import io

# Link-ul direct către cel mai nou zip cu top 1 milion
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
OUTPUT_FILE_NAME = "top-1m.csv" # Numele pe care îl folosește scriptul tău

def download_and_unzip_list():
    print(f"Se descarcă cea mai nouă listă de pe {TRANCO_ZIP_URL}...")
    try:
        # 1. Descarcă fișierul .zip în memorie
        response = requests.get(TRANCO_ZIP_URL)
        response.raise_for_status() # Verifică dacă există erori HTTP

        # 2. Creează un obiect "fișier" virtual din conținutul zip
        zip_file = zipfile.ZipFile(io.BytesIO(response.content))

        # 3. Extrage fișierul CSV din zip
        # (Presupunem că e singurul fișier din zip)
        csv_file_name = zip_file.namelist()[0]
        print(f"Se extrage {csv_file_name}...")

        csv_content = zip_file.read(csv_file_name)

        # 4. Salvează conținutul CSV pe disc
        with open(OUTPUT_FILE_NAME, 'wb') as f:
            f.write(csv_content)

        print(f"Succes! Lista a fost salvată ca {OUTPUT_FILE_NAME}.")

    except Exception as e:
        print(f"EROARE la descărcarea listei: {e}")

if __name__ == "__main__":
    download_and_unzip_list()
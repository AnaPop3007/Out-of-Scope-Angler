const express = require("express");
const axios = require("axios"); // <-- SCHIMBARE: Folosim 'axios' în loc de 'spawn'
const app = express();

app.use(express.static("public"));
app.use(express.json()); // Pentru a citi JSON-ul trimis de frontend

// Adresa la care "locuiește" serverul tău Python (Flask)
// Asigură-te că acesta rulează pe portul 5000!
const PYTHON_API_URL = "http://localhost:5000/check-phishing";

//
// Acesta este endpoint-ul pe care îl va apela frontend-ul tău
//
app.post("/api/process-link", async (req, res) => { // <-- SCHIMBARE: Funcția este 'async'
  
  // 1. Primește link-ul de la frontend (ex: { "link": "http://..." })
  const link = req.body.link;
  if (!link) {
    return res.status(400).json({ error: "No link provided" });
  }

  // 2. SCHIMBARE: Folosim AXIOS pentru a "vorbi" cu serverul Python
  try {
    // Trimite link-ul către serverul Python
    // Atenție: Python (Flask) așteaptă un JSON de forma { "url": "..." }
    const pythonResponse = await axios.post(PYTHON_API_URL, {
      url: link 
    });

    // 3. Trimite răspunsul JSON primit de la Python înapoi la frontend
    // (ex: { risk_score: 55, status: 'Suspicious', ... })
    res.json(pythonResponse.data);

  } catch (error) {
    // Asta se întâmplă dacă serverul Python e oprit sau dă o eroare
    console.error("Eroare la contactarea API-ului Python:", error.message);
    res.status(500).json({ error: "Serviciul de analiză a eșuat" });
  }
});

//
// Pornirea serverului Node.js
//
app.listen(9999, () => {
  console.log("=====================================================");
  console.log("Serverul Node.js (Fațada) rulează pe http://localhost:9999");
  console.log("Frontend-ul este disponibil la http://localhost:9999/index.html");
  console.log("=====================================================");
});
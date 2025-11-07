const express = require("express");
const app = express();

// Serve static files (HTML, CSS, JS) from "public" folder
app.use(express.static("public"));

// Example data to simulate DNS packet info
let dnsPackets = [
  { id: 1, query: "example.com", status: "Resolved", time: "12:30:02" },
  { id: 2, query: "google.com", status: "Resolved", time: "12:30:05" },
  { id: 3, query: "openai.com", status: "Timeout", time: "12:30:07" },
];

// API route to send data to front-end
app.get("/api/dns", (req, res) => {
  res.json(dnsPackets);
});

// Start server
app.listen(9999, () => {
  console.log(" Server running on http://localhost:9999");
});

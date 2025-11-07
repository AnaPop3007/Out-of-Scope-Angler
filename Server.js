const express = require("express");
const { spawn } = require("child_process");
const app = express();

app.use(express.static("public"));
app.use(express.json()); // to parse JSON POST requests

// API route to process link
app.post("/api/process-link", (req, res) => {
  const link = req.body.link;
  if (!link) return res.status(400).json({ error: "No link provided" });

  // Call Python script with the link as parameter
  const pythonProcess = spawn("python", ["process_link.py", link]);

  let output = "";
  pythonProcess.stdout.on("data", (data) => {
    output += data.toString();
  });

  pythonProcess.stderr.on("data", (data) => {
    console.error("Python error:", data.toString());
  });

  pythonProcess.on("close", (code) => {
    if (code === 0) {
      res.json({ result: output.trim() });
    } else {
      res.status(500).json({ error: "Python script failed" });
    }
  });
});

app.listen(9999, () => {
  console.log("Server running on http://localhost:9999");
});

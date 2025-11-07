async function loadDNSData() {
    const response = await fetch("/api/dns");
    const packets = await response.json();
  
    const container = document.querySelector(".sidebar .space-y-3");
    container.innerHTML = ""; // clear old content
  
    packets.forEach(packet => {
      const div = document.createElement("div");
      div.className = "packet-card p-2 rounded bg-gray-800";
      div.textContent = `${packet.id}. ${packet.query} - ${packet.status} @ ${packet.time}`;
      container.appendChild(div);
    });
  }
  
  // Load data every 3 seconds
  loadDNSData();
  setInterval(loadDNSData, 3000);
  
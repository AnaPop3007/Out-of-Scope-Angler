import { initMap, addAlertMarker, drawFlow } from "./components/map.js";
import { initAlertsPanel, addAlertItem } from "./components/alerts.js";
import { initSearch } from "./components/search.js";

let map;
let ws;

// inițializare
document.addEventListener("DOMContentLoaded", () => {
  map = initMap();
  initAlertsPanel();
  initSearch();

  // conectare WebSocket la backend
  ws = new WebSocket("ws://localhost:8000/ws/alerts");
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === "alert") handleAlert(msg.payload);
  };
});

function handleAlert(payload) {
  addAlertMarker(map, payload);
  addAlertItem(payload);
  drawFlow(map, payload.srcCoord, payload.destCoord);
}

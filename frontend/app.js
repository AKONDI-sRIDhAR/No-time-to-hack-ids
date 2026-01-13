async function fetchAlerts() {
  const res = await fetch("http://127.0.0.1:8000/alerts");
  const data = await res.json();
  document.getElementById("alerts").innerText =
    data.map(a => `CRITICAL: ${a.source} PORT ${a.port}`).join("\n");
}

setInterval(fetchAlerts, 2000);

const API_BASE = "/api";

function updateStatus() {
    fetch(`${API_BASE}/devices`) // Check if backend is alive
        .then(res => {
            const el = document.getElementById("system-status");
            el.innerText = `● ONLINE`;
            el.style.color = "#0f0";
        })
        .catch(err => {
            const el = document.getElementById("system-status");
            el.innerText = `● OFFLINE`;
            el.style.color = "red";
        });
}

function updateAlerts() {
    fetch(`${API_BASE}/alerts`)
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById("alerts-log");
            container.innerHTML = "";
            let threatCount = 0;

            data.forEach(alert => {
                const div = document.createElement("div");
                div.className = "log-entry";
                div.innerHTML = `
                    <span class="time">[${alert.timestamp}]</span>
                    <span class="ip">${alert.ip}</span>
                    <span class="type">${alert.type}</span>
                    <span class="action"> >> ${alert.action}</span>
                `;
                container.appendChild(div);
                threatCount++;
            });
            // document.getElementById("threat-count").innerText = threatCount;
        });
}

function updateHoneypot() {
    fetch(`${API_BASE}/honeypot`)
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector("#honeypot-table tbody");
            if (tbody) {
                tbody.innerHTML = "";
                data.forEach(row => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${row.timestamp}</td>
                        <td>${row.ip}</td>
                        <td class="cred">${row.credential}</td>
                        <td class="ua">${row.ua}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        });
}

function updateDevices() {
    fetch(`${API_BASE}/devices`)
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById("devices-list");
            container.innerHTML = "";

            data.forEach(device => {
                const div = document.createElement("div");
                div.className = "asset-card";

                // Status Coloring
                let statusColor = "#ccc"; // Default/Offline
                let borderColor = "#ccc";

                if (device.status === "OFFLINE") {
                    statusColor = "#555";
                    div.style.opacity = "0.6";
                }
                else if (device.status === "IDLE") {
                    statusColor = "#aaa";
                    borderColor = "#aaa";
                }
                else if (device.status === "ONLINE") {
                    statusColor = "lime";
                    borderColor = "lime";
                }
                else if (device.status === "SUSPICIOUS") {
                    statusColor = "orange";
                    borderColor = "orange";
                }
                else if (device.status === "DECEIVED") {
                    statusColor = "#d600d6"; // Purple
                    borderColor = "#d600d6";
                }
                else if (device.status === "NEW/QUARANTINED" || device.status === "QUARANTINED") {
                    statusColor = "yellow";
                    borderColor = "yellow";
                }
                else if (device.status === "CONTAINED" || device.status === "BLOCKED") {
                    statusColor = "red";
                    borderColor = "red";
                }

                div.style.borderLeft = `4px solid ${borderColor}`;

                // Hostname handling
                const displayName = (device.hostname && device.hostname !== "unknown") ? device.hostname : "Unknown Device";

                let trust = device.trust_score !== undefined ? device.trust_score : '?';

                div.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                        <span style="font-size:0.9rem; font-weight:bold; color:${statusColor}">${displayName}</span>
                        <span style="font-size:0.75rem; color:#888;">${device.ip}</span>
                    </div>
                    
                    <div style="font-size:0.75rem; color:#666; margin-bottom:5px;">MAC: ${device.mac}</div>
                    
                    <div style="font-size:0.75rem; color:#aaa; margin-bottom:10px;">
                        Trust: <b>${trust}%</b> | Status: <b>${device.status}</b>
                    </div>

                    <div class="action-buttons" style="display:flex; justify-content:space-between; gap:2px;">
                        <button class="btn-xs" style="background:#555;" onclick="triggerAction('release', '${device.ip}')" title="Release">REL</button>
                        <button class="btn-xs" style="background:purple;" onclick="triggerAction('redirect', '${device.ip}')" title="Deceive">DEC</button>
                        <button class="btn-xs" style="background:orange;" onclick="triggerAction('quarantine', '${device.ip}')" title="Quarantine">Q</button>
                        <button class="btn-xs" style="background:red;" onclick="triggerAction('block', '${device.ip}')" title="Block MAC">BLK</button>
                        <button class="btn-xs" style="background:darkred;" onclick="triggerAction('kick', '${device.ip}')" title="Kick">KICK</button>
                    </div>
                `;
                container.appendChild(div);
            });
        });
}

function triggerAction(action, ip) {
    if (!confirm(`CONFIRM: ${action.toUpperCase()} ${ip}?`)) return;

    fetch(`${API_BASE}/action/${action}/${ip}`, { method: "POST" })
        .then(async res => {
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || "Unknown Error");
            }
            return res.json();
        })
        .then(data => {
            console.log(`Action ${action} succeeded on ${ip}`);
            updateDevices(); // Refresh immediately
        })
        .catch(err => {
            alert(`Action Failed: ${err.message}`);
        });
}

function activateDoomsday() {
    if (confirm("⚠ WARNING: ACTIVATE NETWORK LOCKDOWN? ALL TRAFFIC WILL BE DROPPED.")) {
        fetch(`${API_BASE}/doomsday`, { method: "POST" })
            .then(res => res.json())
            .then(data => {
                alert("NETWORK LOCKED DOWN");
            });
    }
}

// Poll Loop
setInterval(() => {
    updateStatus();
    updateAlerts();
    updateHoneypot();
    updateDevices();
}, 2000);

// Init
updateStatus();
updateAlerts();
updateHoneypot();
updateDevices();

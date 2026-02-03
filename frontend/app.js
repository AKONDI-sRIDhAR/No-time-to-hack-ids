const API_BASE = "/api";

function updateStatus() {
    fetch(`${API_BASE}/status`)
        .then(res => res.json())
        .then(data => {
            const el = document.getElementById("system-status");
            el.innerText = `● ${data.status}`;
            if (data.status === "LOCKDOWN") {
                el.style.color = "red";
                el.style.borderColor = "red";
                document.body.style.border = "5px solid red";
            }
        });
}

function updateAlerts() {
    fetch(`${API_BASE}/alerts`)
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById("alerts-log");
            container.innerHTML = "";
            const uniqueThreats = new Set();

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
                uniqueThreats.add(alert.ip);
            });

            // Update Threat Count
            document.getElementById("threat-count").innerText = uniqueThreats.size;
        });
}

function updateHoneypot() {
    fetch(`${API_BASE}/honeypot`)
        .then(res => res.json())
        .then(data => {
            const tbody = document.querySelector("#honeypot-table tbody");
            tbody.innerHTML = "";
            data.forEach(row => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${row.timestamp}</td>
                    <td>${row.ip}</td>
                    <td class="cred">${row.credential}</td>
                    <td>${row.ua}</td>
                `;
                tbody.appendChild(tr);
            });
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

                // Styling based on Lifecycle State
                let borderColor = "#333";
                let statusColor = "lime";

                if (device.status === "OFFLINE") {
                    statusColor = "#555";
                    div.style.opacity = "0.6";
                } else if (device.status === "NEW/QUARANTINED") {
                    statusColor = "yellow";
                    borderColor = "yellow";
                } else if (device.status === "SUSPICIOUS") {
                    statusColor = "orange";
                    borderColor = "orange";
                } else if (device.status === "DECEIVED") {
                    statusColor = "#ff00ff"; // Purple for honeypot
                    borderColor = "#ff00ff";
                } else if (device.status === "CONTAINED") {
                    statusColor = "red";
                    borderColor = "red";
                }

                div.style.borderColor = borderColor;

                div.innerHTML = `
                    <div class="asset-ip">${device.ip}</div>
                    <div style="font-size:0.7rem; color:#888;">${device.mac}</div>
                    <div style="margin: 8px 0; font-size: 0.9rem; font-weight: bold; color: ${statusColor}">
                         ${device.status}
                    </div>
                    <div style="font-size:0.8rem;">
                         Trust Score: <b>${device.trust_score !== undefined ? device.trust_score : '?'}</b>
                    </div>
                    <div style="margin-top:5px; font-size:0.7rem; color:#aaa;">
                        PKTS: ${device.packets} | PORTS: ${device.ports}
                    </div>
                    <div class="action-buttons" style="margin-top:8px; display:flex; gap:4px; justify-content:center;">
                        <button class="btn-xs" style="background:#555;" onclick="triggerAction('release', '${device.ip}')">REL</button>
                        <button class="btn-xs" style="background:orange;" onclick="triggerAction('quarantine', '${device.ip}')">Q</button>
                        <button class="btn-xs" style="background:purple;" onclick="triggerAction('redirect', '${device.ip}')">DEC</button>
                        <button class="btn-xs" style="background:red;" onclick="triggerAction('isolate', '${device.ip}')">BLOCK</button>
                    </div>
                `;
                container.appendChild(div);
            });
        });
}

function triggerAction(action, ip) {
    if (!confirm(`Confirm ${action.toUpperCase()} for ${ip}?`)) return;

    fetch(`/api/action/${action}/${ip}`, { method: "POST" })
        .then(res => res.json())
        .then(data => {
            alert(`Action ${action} executed on ${ip}`);
            updateDevices();
        })
        .catch(err => alert("Action failed: " + err));
}

function activateDoomsday() {
    if (confirm("CONFIRM: ACTIVATE NETWORK LOCKDOWN? THIS WILL ISOLATE ALL DEVICES.")) {
        fetch(`${API_BASE}/doomsday`, { method: "POST" })
            .then(res => res.json())
            .then(data => {
                alert("DOOMSDAY PROTOCOL INITIATED");
                updateStatus();
            });
    }
}

// Loop
setInterval(() => {
    updateStatus();
    updateAlerts();
    updateHoneypot();
    updateDevices();
}, 2000);

// Initial call
updateStatus();
updateAlerts();
updateHoneypot();
updateDevices();

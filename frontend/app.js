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
                if (device.status === "SUSPICIOUS") div.style.borderColor = "red";
                
                div.innerHTML = `
                    <div class="asset-ip">${device.ip}</div>
                    <div style="font-size:0.7rem; color:#888;">${device.mac}</div>
                    <div style="margin-top:5px; font-size:0.8rem;">
                        PKTS: ${device.packets} | PORTS: ${device.ports}
                    </div>
                    <div style="color:${device.status === 'ONLINE' ? 'lime' : 'red'}; font-weight:bold;">
                        ${device.status}
                    </div>
                `;
                container.appendChild(div);
            });
        });
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

const API_BASE = "/api";

function statusView(status) {
    const table = {
        OFFLINE: { color: "#666", cls: "state-offline", icon: "O" },
        IDLE: { color: "#9a9a9a", cls: "state-idle", icon: "I" },
        ONLINE: { color: "#00ff41", cls: "state-online", icon: "N" },
        SUSPICIOUS: { color: "#ff9f1a", cls: "state-suspicious", icon: "!" },
        DECEIVED: { color: "#34d399", cls: "state-deceived", icon: "D" },
        QUARANTINED: { color: "#facc15", cls: "state-quarantined", icon: "Q" },
        ISOLATED: { color: "#ff003c", cls: "state-isolated", icon: "X" }
    };
    return table[status] || { color: "#ccc", cls: "", icon: "?" };
}

function updateStatus() {
    fetch(`${API_BASE}/devices`)
        .then(() => {
            const el = document.getElementById("system-status");
            el.innerText = "o ONLINE";
            el.style.color = "#00ff41";
        })
        .catch(() => {
            const el = document.getElementById("system-status");
            el.innerText = "o OFFLINE";
            el.style.color = "#ff003c";
        });
}

function updateAlerts() {
    fetch(`${API_BASE}/alerts`)
        .then((res) => res.json())
        .then((data) => {
            const container = document.getElementById("alerts-log");
            container.innerHTML = "";
            let threatCount = 0;

            data.forEach((alert) => {
                const div = document.createElement("div");
                div.className = "log-entry";
                div.innerHTML = `
                    <span class="time">[${alert.timestamp}]</span>
                    <span class="ip">${alert.ip}</span>
                    <span class="type">${alert.type}</span>
                    <span class="action"> >> ${alert.action}</span>
                `;
                container.appendChild(div);
                threatCount += 1;
            });

            const c = document.getElementById("threat-count");
            if (c) c.innerText = String(threatCount);
        });
}

function updateHoneypot() {
    fetch(`${API_BASE}/honeypot`)
        .then((res) => res.json())
        .then((data) => {
            const tbody = document.querySelector("#honeypot-table tbody");
            if (!tbody) return;

            tbody.innerHTML = "";
            data.forEach((row) => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${row.timestamp || ""}</td>
                    <td>${row.ip || ""}</td>
                    <td>${row.service || ""}</td>
                    <td class="cred">${row.credential || ""}</td>
                    <td class="ua">${row.ua || ""}</td>
                `;
                tbody.appendChild(tr);
            });
        });
}

function updateDevices() {
    fetch(`${API_BASE}/devices`)
        .then((res) => res.json())
        .then((data) => {
            const container = document.getElementById("devices-list");
            container.innerHTML = "";

            data.forEach((device) => {
                const div = document.createElement("div");
                const view = statusView(device.status);
                div.className = `asset-card ${view.cls}`;

                const displayName = (device.hostname && device.hostname !== "unknown")
                    ? device.hostname
                    : "Unknown Device";
                const trust = device.trust_score !== undefined ? device.trust_score : "?";
                const reason = device.reason ? device.reason : "-";

                div.innerHTML = `
                    <div class="asset-top">
                        <span class="asset-name" style="color:${view.color}">[${view.icon}] ${displayName}</span>
                        <span class="asset-ip">${device.ip}</span>
                    </div>
                    <div class="asset-meta">MAC: ${device.mac}</div>
                    <div class="asset-meta">Trust: <b>${trust}%</b> | Status: <b>${device.status}</b></div>
                    <div class="asset-reason">Attack: ${reason}</div>
                    <div class="action-buttons">
                        <button class="btn-xs btn-release" onclick="triggerAction('release', '${device.ip}')" title="Release">REL</button>
                        <button class="btn-xs btn-redirect" onclick="triggerAction('redirect', '${device.ip}')" title="Redirect">REDIR</button>
                        <button class="btn-xs btn-quarantine" onclick="triggerAction('quarantine', '${device.ip}')" title="Quarantine">QUAR</button>
                        <button class="btn-xs btn-isolate" onclick="triggerAction('isolate', '${device.ip}')" title="Isolate">ISO</button>
                    </div>
                `;
                container.appendChild(div);
            });
        });
}

function triggerAction(action, ip) {
    if (!confirm(`CONFIRM: ${action.toUpperCase()} ${ip}?`)) return;

    fetch(`${API_BASE}/action/${action}/${ip}`, { method: "POST" })
        .then(async (res) => {
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.error || "Unknown Error");
            }
            return res.json();
        })
        .then(() => {
            updateDevices();
            updateAlerts();
        })
        .catch((err) => {
            alert(`Action Failed: ${err.message}`);
        });
}

function activateDoomsday() {
    if (confirm("WARNING: Activate lockdown? All forwarding traffic will be dropped.")) {
        fetch(`${API_BASE}/doomsday`, { method: "POST" })
            .then((res) => res.json())
            .then(() => {
                alert("NETWORK LOCKED DOWN");
            });
    }
}

setInterval(() => {
    updateStatus();
    updateAlerts();
    updateHoneypot();
    updateDevices();
}, 2000);

updateStatus();
updateAlerts();
updateHoneypot();
updateDevices();

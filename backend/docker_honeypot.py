import subprocess
import os

HONEYPOT_CONTAINERS = {
    "ntth-device": {
        "image": "cowrie/cowrie",
        "ports": ["2222:2222"]
    },
    "http-hp": {
        "image": "nginx",
        "ports": ["8080:80"]
    },
    "smb-honeypot": {
        "image": "dinotools/dionaea",
        "ports": ["445:445"]
    }
}

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HONEYPOT_LOG = os.path.join(DATA_DIR, "honeypot.csv")


def run(cmd):
    return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ensure_image_built():
    # Images are pulled automatically by docker run if missing
    pass


def start_honeypot():
    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(HONEYPOT_LOG):
        with open(HONEYPOT_LOG, "w") as f:
            f.write("timestamp,ip,service,username,password,ua\n")

    for name, cfg in HONEYPOT_CONTAINERS.items():
        check = subprocess.run(
            f"docker ps --format '{{{{.Names}}}}' | grep -w {name}",
            shell=True,
            stdout=subprocess.PIPE
        )

        if check.stdout.strip():
            continue

        port_args = " ".join([f"-p {p}" for p in cfg["ports"]])
        cmd = f"docker run -d --name {name} {port_args} {cfg['image']}"
        run(cmd)

        print(f"[HONEYPOT] {name} started")


def parse_logs():
    """
    Lightweight log harvesting (demo-safe).
    """
    for name in HONEYPOT_CONTAINERS.keys():
        result = subprocess.run(
            f"docker logs --since 5s {name}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        lines = result.stdout.decode(errors="ignore").splitlines()
        if not lines:
            continue

        with open(HONEYPOT_LOG, "a") as f:
            for line in lines:
                f.write(f"{line}\n")

NTTH Portable Honeypot 🍯

This project contains a fully containerized, portable honeypot designed to emulate a vulnerable device. It listens on SSH, HTTP, and SMB ports to log attacker activity without exposing the host machine to real danger.

Repository: https://github.com/Sujith1911/NoTimeToHack

🛠️ 1. Prerequisites (Setup Docker)

Before running the honeypot, your Linux machine needs Docker installed.

Run these commands on the host machine:

# Update package list and install Docker
sudo apt-get update
sudo apt-get install -y docker.io

# Start and Enable Docker service to run on boot
sudo systemctl start docker
sudo systemctl enable docker


(Optional) To run docker without sudo, run sudo usermod -aG docker $USER and then reboot.

📥 2. Installation

Step A: Clone the Repository

Download the project files to your machine.

git clone [https://github.com/Sujith1911/NoTimeToHack.git](https://github.com/Sujith1911/NoTimeToHack.git)
cd NoTimeToHack


Step B: Build the Docker Image

This command reads the Dockerfile and builds the secure environment.

# Build the image and tag it as 'ntth-honeypot' version 1
sudo docker build -t ntth-honeypot:v1 .


Note: This process may take a few minutes as it downloads the Python base and installs dependencies.

🚀 3. Running the Honeypot

Once built, you need to run the container. We will map the "Fake" internal ports to the "Real" external ports on your machine.

Service

Internal Port

External Port (What attackers see)

SSH

2222

22

HTTP

8080

80

SMB

4445

445

Run this command to start:

sudo docker run -d \
    -p 22:2222 \
    -p 80:8080 \
    -p 445:4445 \
    --name ntth-device \
    ntth-honeypot:v1


🧪 4. Testing & Verification

How to confirm the honeypot is working:

Test 1: Check if Container is Running

sudo docker ps


You should see ntth-device in the list.

Test 2: Port Scan (Nmap)

Check if the ports are open and visible.

nmap -p 22,80,445 localhost


Test 3: Attempt an SSH Login

Try to log in as an attacker would.

ssh root@localhost


Any password should work (or fail depending on config), but the attempt will be logged.

📊 5. Viewing Logs (Forensics)

To see what the attackers (or you) are doing in real-time:

sudo docker logs -f ntth-device


🛑 Management Commands

# Stop the honeypot
sudo docker stop ntth-device

# Start it again
sudo docker start ntth-device

# Remove the container (if you need to delete it)
sudo docker rm ntth-device

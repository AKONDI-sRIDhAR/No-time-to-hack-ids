# Use a lightweight Python base (Updated to bookworm to fix apt-get 404 errors)
FROM python:3.9-slim-bookworm

# Install system dependencies including those for SMB/HTTP emulation
# The backslashes (\) at the end of lines are MANDATORY for multiline commands
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev \
    build-essential \
    git \
    authbind \
    && rm -rf /var/lib/apt/lists/*

# Create user NTTH
RUN adduser --disabled-password --gecos "" ntth

# Install Cowrie (Handles SSH and Telnet)
USER ntth
WORKDIR /home/ntth

# Corrected git clone command - purely the URL, no markdown syntax
RUN git clone https://github.com/cowrie/cowrie.git

WORKDIR /home/ntth/cowrie

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy default config and set hostname to NTTH-Device
RUN cp etc/userdb.example etc/userdb.txt && \
    cp etc/cowrie.cfg.dist etc/cowrie.cfg && \
    sed -i 's/hostname = .*/hostname = NTTH-Computer/' etc/cowrie.cfg

# Expose internal ports (2222:SSH, 8080:HTTP, 4445:SMB)
EXPOSE 2222 8080 4445

# Start command
CMD ["python", "bin/cowrie", "start", "-n"]

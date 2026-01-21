FROM python:3.9-slim

RUN apt update && apt install -y \
    git \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create cowrie user
RUN useradd -m cowrie

# Clone cowrie
WORKDIR /opt
RUN git clone https://github.com/cowrie/cowrie.git

# Install cowrie deps
WORKDIR /opt/cowrie
RUN pip install --no-cache-dir -r requirements.txt

# Create default config
RUN cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Fix permissions
RUN chown -R cowrie:cowrie /opt/cowrie

USER cowrie

EXPOSE 2222 8080 4445

CMD ["/opt/cowrie/bin/cowrie", "start", "-n"]

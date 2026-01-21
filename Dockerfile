FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    git \
    iproute2 \
    net-tools \
    procps \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ntth

WORKDIR /home/ntth
RUN git clone https://github.com/cowrie/cowrie.git

WORKDIR /home/ntth/cowrie

RUN pip install --no-cache-dir -r requirements.txt

# Runtime directories REQUIRED by Cowrie
RUN mkdir -p var/log/cowrie \
             var/lib/cowrie \
             var/run/cowrie

RUN cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Listen on all interfaces
RUN sed -i 's/^# listen_endpoints/listen_endpoints/' etc/cowrie.cfg && \
    sed -i 's/127.0.0.1/0.0.0.0/' etc/cowrie.cfg

RUN chown -R ntth:ntth /home/ntth/cowrie

USER ntth
EXPOSE 2222

CMD ["bin/cowrie", "start", "-n"]

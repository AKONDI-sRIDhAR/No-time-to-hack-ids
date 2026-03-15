FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV COWRIE_HOME=/opt/cowrie

RUN apt-get update && apt-get install -y \
    git \
    samba \
    smbclient \
    procps \
    iproute2 \
    net-tools \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ntth

WORKDIR /opt
RUN git clone --depth=1 https://github.com/cowrie/cowrie.git "${COWRIE_HOME}"

WORKDIR ${COWRIE_HOME}
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p \
    ${COWRIE_HOME}/var/log/cowrie \
    ${COWRIE_HOME}/var/lib/cowrie \
    ${COWRIE_HOME}/var/run/cowrie \
    /srv/public \
    /var/log/samba \
    /opt/honeypot

COPY backend/cowrie.cfg ${COWRIE_HOME}/etc/cowrie.cfg
COPY backend/smb.conf /etc/samba/smb.conf
COPY backend/fake_admin.py /opt/honeypot/fake_admin.py
COPY backend/honeypot_entrypoint.sh /opt/honeypot/entrypoint.sh

RUN printf '%s\n' \
    'Quarterly planning workbook' \
    'VPN inventory' \
    'Edge credentials rotation schedule' \
    > /srv/public/roadmap.txt && \
    printf '%s\n' \
    'username,password,role' \
    'admin,Summer2024!,superuser' \
    'operator,Welcome123,ops' \
    > /srv/public/users.csv && \
    chmod 644 /srv/public/roadmap.txt /srv/public/users.csv && \
    chown -R ntth:ntth ${COWRIE_HOME} && \
    chmod +x /opt/honeypot/entrypoint.sh && \
    touch /var/log/samba/log.smbd

EXPOSE 2222 8080 445

CMD ["/opt/honeypot/entrypoint.sh"]

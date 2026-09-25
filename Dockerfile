# netassess — self-contained image: the tool + nmap + nuclei + feroxbuster,
# with nuclei templates baked in. No host installs required.
#
#   docker build -t netassess .
#   docker run --rm -v "$PWD:/work" netassess network scan --targets targets.txt
#
# Persist CVE/KEV caches and nuclei templates across runs with a named volume:
#   docker run --rm -v "$PWD:/work" -v netassess-data:/root/.netassess netassess ...
#
# NOTE: prebuilt tool binaries are fetched for linux/amd64. On Apple Silicon,
# build with:  docker build --platform linux/amd64 -t netassess .
FROM python:3.12-slim

LABEL org.opencontainers.image.title="netassess" \
      org.opencontainers.image.source="https://github.com/Cyberlord246/netassess" \
      org.opencontainers.image.description="Authorized, safe network attack-surface assessment platform"

# --- system tools ---------------------------------------------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap ca-certificates curl unzip tar \
 && rm -rf /var/lib/apt/lists/*

# --- nuclei (latest linux/amd64 release) ----------------------------------
RUN set -eux; \
    url="$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep browser_download_url | grep -i 'linux_amd64.zip' | head -1 | cut -d '"' -f4)"; \
    curl -sSL "$url" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    rm /tmp/nuclei.zip; chmod +x /usr/local/bin/nuclei; \
    nuclei -version

# --- feroxbuster (latest linux/amd64 release) -----------------------------
RUN set -eux; \
    url="$(curl -sSL https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | grep browser_download_url | grep -i 'x86_64-linux-feroxbuster.tar.gz' | head -1 | cut -d '"' -f4)"; \
    curl -sSL "$url" -o /tmp/ferox.tar.gz; \
    tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster; \
    rm /tmp/ferox.tar.gz; chmod +x /usr/local/bin/feroxbuster; \
    feroxbuster --version

# --- bake nuclei templates into the image (so runs need no update) --------
RUN nuclei -update-templates -duc || echo "template fetch skipped (fetch at runtime if needed)"

# --- install netassess ----------------------------------------------------
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# quick sanity check that everything is wired
RUN netassess scope check --targets 192.0.2.0/30 >/dev/null \
 && echo "netassess installed OK"

# work in a mounted directory (targets.txt, outputs live here)
WORKDIR /work
ENTRYPOINT ["netassess"]
CMD ["--help"]

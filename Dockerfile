# netassess — self-contained image: the tool + nmap + nuclei + feroxbuster,
# with nuclei templates baked in. No host installs required.
#
#   docker build -t netassess .
#   docker run --rm -v "$PWD:/work" netassess network scan --targets targets.txt
#
# Persist CVE/KEV caches and nuclei templates across runs with a named volume:
#   docker run --rm -v "$PWD:/work" -v netassess-data:/root/.netassess netassess ...
#
# Runs anywhere Docker runs (macOS, Linux/Ubuntu, Windows). The image is Linux;
# tool binaries are selected for the build architecture (amd64 or arm64), so a
# plain `docker build` produces a native image on both Intel/AMD and Apple
# Silicon. If a tool has no binary for the arch, it's skipped and netassess uses
# its built-in fallback.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="netassess" \
      org.opencontainers.image.source="https://github.com/Cyberlord246/netassess" \
      org.opencontainers.image.description="Authorized, safe network attack-surface assessment platform"

# --- system tools ---------------------------------------------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap ca-certificates curl unzip tar \
 && rm -rf /var/lib/apt/lists/*

# --- nuclei + feroxbuster (arch-aware; best-effort, non-fatal) -------------
# TARGETARCH is provided automatically by BuildKit (amd64 / arm64). Tool
# installs are best-effort: if a download fails or has no matching binary, the
# build still succeeds and netassess uses its built-in fallbacks.
ARG TARGETARCH
RUN set -ux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) NARCH="linux_amd64"; FARCH="x86_64-linux" ;; \
      arm64) NARCH="linux_arm64"; FARCH="aarch64-linux" ;; \
      *)     NARCH="linux_amd64"; FARCH="x86_64-linux" ;; \
    esac; \
    # extract browser_download_url values even from minified JSON
    nurl="$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -oE '\"browser_download_url\":[[:space:]]*\"[^\"]+\"' \
        | sed -E 's/.*\"(https[^\"]+)\"/\1/' | grep -i "${NARCH}\.zip" | head -1)"; \
    if [ -n "$nurl" ]; then \
        curl -sSL "$nurl" -o /tmp/nuclei.zip \
        && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
        && chmod +x /usr/local/bin/nuclei && nuclei -version \
        || echo "nuclei install failed — skipping"; \
        rm -f /tmp/nuclei.zip; \
    else echo "nuclei: no ${NARCH} asset — skipping (netassess still runs)"; fi; \
    furl="$(curl -sSL https://api.github.com/repos/epi052/feroxbuster/releases/latest \
        | grep -oE '\"browser_download_url\":[[:space:]]*\"[^\"]+\"' \
        | sed -E 's/.*\"(https[^\"]+)\"/\1/' | grep -i "${FARCH}-feroxbuster\.tar\.gz" | head -1)"; \
    if [ -n "$furl" ]; then \
        curl -sSL "$furl" -o /tmp/ferox.tar.gz \
        && tar -xzf /tmp/ferox.tar.gz -C /usr/local/bin feroxbuster \
        && chmod +x /usr/local/bin/feroxbuster && feroxbuster --version \
        || echo "feroxbuster install failed — skipping"; \
        rm -f /tmp/ferox.tar.gz; \
    else echo "feroxbuster: no ${FARCH} asset — built-in content discovery will be used"; fi

# --- bake nuclei templates into the image (so runs need no update) --------
RUN nuclei -update-templates 2>/dev/null || echo "template fetch skipped (nuclei absent or offline; fetch at runtime)"

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

# syntax=docker/dockerfile:1

# MOLE — scope-gated, LLM-driven security reconnaissance harness.
# The LLM runs outside the container (OpenAI-compatible endpoint via
# MOLE_LLM_BASE_URL / MOLE_LLM_API_KEY / MOLE_LLM_MODEL); this image
# only bundles the harness and its recon + opt-in exploitation tooling.

FROM golang:1.27 AS build
WORKDIR /src
# Dependencies (incl. agent-core) are vendored, so the module build needs no
# GitLab access. (The nuclei/ffuf installs below still fetch from the network.)
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mole .
# Vulnerability-scanning tooling (opt-in via vuln_scanning: true). Inert for recon-only
# engagements — the registry gate keeps it unreachable — but bundled so the
# image is self-contained. Templates are fetched by nuclei on first use.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/ffuf/ffuf/v2@latest

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        dnsutils \
        git \
        python3 \
        python3-requests \
        hashcat \
        ncat \
        curl \
    && rm -rf /var/lib/apt/lists/*
# Metasploit payload generation (msfvenom) via the official self-extracting
# installer (no versioned archive exists; -latest- matches the go install
# pattern above). Stateless use only — no msfconsole, no services. The
# installer lands the launcher at <prefix>/app/msfvenom (it also symlinks
# /usr/local/bin/msfvenom itself; we re-link it explicitly so the build
# fails loudly if that ever changes).
RUN curl -fsSL -o /tmp/metasploit.run https://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run \
    && chmod +x /tmp/metasploit.run \
    && /tmp/metasploit.run --mode unattended --unattendedmodeui none --prefix /opt/metasploit --baseunixservice_install_as_service 0 \
    && ln -sf /opt/metasploit/app/msfvenom /usr/local/bin/msfvenom \
    && rm -f /tmp/metasploit.run \
    && msfvenom --version
COPY --from=build /out/mole /usr/local/bin/mole
COPY --from=build /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=build /go/bin/ffuf /usr/local/bin/ffuf
# Bundled wordlist for the crack tool (SecLists Pwdb_top-1000.txt).
COPY data/wordlists/top1000.txt /usr/share/mole/wordlists/top1000.txt
WORKDIR /work
ENTRYPOINT ["mole"]
CMD ["help"]

# syntax=docker/dockerfile:1

# MOLE — scope-gated, LLM-driven security reconnaissance harness.
# The LLM runs outside the container (OpenAI-compatible endpoint via
# MOLE_LLM_BASE_URL / MOLE_LLM_API_KEY / MOLE_LLM_MODEL); this image
# only bundles the harness and its recon tooling.

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
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mole /usr/local/bin/mole
COPY --from=build /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=build /go/bin/ffuf /usr/local/bin/ffuf
WORKDIR /work
ENTRYPOINT ["mole"]
CMD ["help"]

# MOLE

AI-driven offensive security recon for a single engagement. This repo holds
two things:

| Path          | What it is                                                                 |
|---------------|----------------------------------------------------------------------------|
| `mole`        | This front-end: builds the image, collects the LLM config, asks for an objective, runs the container and tails its output |
| `harness/`    | The MOLE harness itself (agent loop, tools, reporting) — see `harness/README.md` |
| `engagement/` | Per-engagement data: `scope.yaml`, reports, transcripts (gitignored)       |

## Quick start

```sh
go build -o mole .
./mole
```

`mole` walks through four steps:

1. **Docker image** — fingerprints the `harness/` build context (SHA-256 of
   the context files, respecting `.dockerignore`, plus `Dockerfile` and
   `.dockerignore`) and compares it to the `mole.version` label on the local
   image. The image is rebuilt only when it is missing, has no version label,
   or a newer version is available; an up-to-date image is reused after a
   `Rebuild anyway [y/N]` confirm (default: keep the current image).
2. **Configure** — prompts for the LLM environment and writes `launcher.env`
   (prefilled from any existing config; values are passed to the container
   via `-e` since the LLM stays outside)
3. **Objective** — asks for the recon objective
4. **Run** — `docker run`s the image with the engagement volume mounted and
   streams (tails) the container output to the terminal

When it finishes, the report and transcript land in
`engagement/<name>/` (e.g. `engagement/cubyte/`).

### Flags

```
-image        Docker image tag (default "mole")
-config       config file path (default "launcher.env")
-engagement   engagement name, e.g. cubyte
-dir          engagement directory (default "engagement")
-objective    objective text (skips the prompt)
-max-steps    tool-step budget (0 = harness default)
-network      docker network, e.g. host (LAN-only targets)
-no-build     skip the image build entirely (no context check, no prompt)
-no-add-host  don't map host.docker.internal (remote LLM)
-dry-run      print the planned build and the docker run command; skips the
              image check
```

## LLM

The LLM runs **outside** the container and is reached via
`MOLE_LLM_BASE_URL` (defaults to `http://host.docker.internal:8080/v1`,
mapped into the container with `--add-host=host.docker.internal:host-gateway`)
and `MOLE_LLM_MODEL` (defaults to `swift-qwen3.8-27b`).
`MOLE_LLM_API_KEY` is optional and only sent when set.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

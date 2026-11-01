# MOLE

<p align="center">
  <img src="assets/mole.png" alt="Cyberpunk Mole" width="420">
</p>

AI-driven offensive security recon for a single engagement. This repo holds
three things:

| Path          | What it is                                                                 |
|---------------|----------------------------------------------------------------------------|
| `mole`        | This front-end: pulls (or builds) the image, collects the LLM config, asks for an objective, runs the container and tails its output |
| `harness/`    | The MOLE harness itself (agent loop, tools, reporting) — see `harness/README.md` |
| `engagement/` | Per-engagement data: `scope.yaml`, reports, transcripts (gitignored)       |

## Quick start

First build the launcher front-end:

```sh
go build -o mole .
```

### Scope an engagement

```sh
./mole init
```

`mole init` walks the scoping wizard (name, authorisation basis, in/out of
scope, ports, and the vulnerability-scanning opt-in) and writes
`engagement/<name>/scope.yaml` — the same file `harness mole init` writes,
so an engagement created this way works with the harness unchanged. It needs
no docker and no harness build.

### Run the engagement

```sh
./mole
```

That `./mole` run walks through five steps:

1. **Docker image** — by default pulls the image from the registry: a missing
   image is downloaded, a newer one is offered, and if the registry can't be
   reached the local image is used as is. With `-build` it builds locally
   instead: it fingerprints the `harness/` build context (SHA-256 of the
   context files, respecting `.dockerignore`, plus `Dockerfile` and
   `.dockerignore`) and compares it to the `mole.version` label on the local
   image, rebuilding only when the image is missing, has no version label, or a
   newer version is available; an up-to-date image is reused after a
   `Rebuild anyway [y/N]` confirm (default: keep the current image).
2. **Configure** — prompts for the LLM environment and writes `launcher.env`
   (prefilled from any existing config; values are passed to the container
   via `-e` since the LLM stays outside)
3. **Objective** — asks for the recon objective
4. **Vulnerability scanning** — shows the engagement's recorded state and
   offers to change it (enabling is opt-in and requires a typed `YES`); when
   no engagement exists at all, it offers to run `mole init` inline
5. **Run** — `docker run`s the image with the engagement volume mounted and
   streams (tails) the container output to the terminal

When it finishes, the report and transcript land in
`engagement/<name>/` (e.g. `engagement/cubyte/`).

### Flags

```
-image        Docker image tag (default "cubyteimages/cubyte-mole:latest")
-config       config file path (default "launcher.env")
-engagement   engagement name, e.g. cubyte
-dir          engagement directory (default "engagement")
-objective    objective text (skips the prompt)
-max-steps    tool-step budget (0 = harness default)
-network      docker network, e.g. host (LAN-only targets)
-build        build the image locally instead of pulling it
-no-build     skip step 1 and use the local image as is (no pull, no build)
-no-add-host  don't map host.docker.internal (remote LLM)
-dry-run      print the planned docker commands without executing them
```

### The `init` subcommand

```
mole init [-dir DIR] [-engagement NAME] [-dry-run]
```

Runs the scoping wizard and writes `engagement/<name>/scope.yaml` (mode
0600). `-engagement` prefills the name prompt (press Enter to keep it);
`-dry-run` prints the planned file without writing.

## LLM

The LLM runs **outside** the container and is reached via
`MOLE_LLM_BASE_URL` (defaults to `http://host.docker.internal:8080/v1`,
mapped into the container with `--add-host=host.docker.internal:host-gateway`)
and `MOLE_LLM_MODEL` (defaults to `swift-qwen3.8-27b`).
`MOLE_LLM_API_KEY` is optional and only sent when set.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

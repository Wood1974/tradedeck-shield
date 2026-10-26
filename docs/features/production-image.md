# Production image and requirements

- `server/requirements.txt` is what the server needs to run. The production image installs only that.
- `server/requirements-dev.txt` is that plus what the tests need (`pytest`). CI and the nightly fuzz install it.
- Removed from the runtime list because nothing imports them: `pytest` (tests only) and `pydantic-settings` (no use anywhere in the repo).
- Both Dockerfiles (`Dockerfile`, used by Render, and `server/Dockerfile`) have a `HEALTHCHECK` on `/health`. Render uses its own `healthCheckPath`; this is for anywhere else the image runs.

**Not done:** pinning the base image to a digest. It needs a digest checked against Docker Hub, which was not available from the build environment; `python:3.12-slim` still floats within 3.12.
**Not verified:** a Docker build of the image (no Docker daemon in the build environment). The app was imported with only the production requirements installed in a fresh environment (45 routes), and the full test suite was run with only `requirements-dev.txt` installed.

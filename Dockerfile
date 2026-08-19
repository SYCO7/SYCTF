# SYCTF — autonomous, menu-driven CTF framework
# Build:  docker build -t syctf .
# Run:    docker run --rm -it syctf shell
# Solve:  docker run --rm -it syctf solve "ZmxhZ3toaX0="
# AI:     docker run --rm -it -e OPENAI_API_KEY=sk-... syctf agent ./chal
#         (local Ollama: run with --network host and set SYCTF_AI_PROVIDER=ollama)

FROM python:3.12-slim

LABEL org.opencontainers.image.title="SYCTF" \
      org.opencontainers.image.description="Autonomous, menu-driven CTF framework with multi-provider AI" \
      org.opencontainers.image.source="https://github.com/SYCO7/SYCTF" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Install SYCTF itself.
COPY . /app
RUN pip install .

# Non-root by default.
RUN useradd -m -u 10001 ctf && chown -R ctf:ctf /app
USER ctf
WORKDIR /work

ENTRYPOINT ["syctf"]
CMD ["--help"]

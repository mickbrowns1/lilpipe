# Pipeline Lab: Python server + Vector + LuaJIT in one small image.
# Build:  docker compose up -d --build        (see docker-compose.yml)

# Vector binary comes from the official image, so no download or install step here.
# To use a different Vector version:  docker compose build --build-arg VECTOR_VERSION=0.61.0
ARG VECTOR_VERSION=0.61.0
FROM timberio/vector:${VECTOR_VERSION}-debian AS vector

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends luajit ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=vector /usr/bin/vector /usr/local/bin/vector

RUN useradd --create-home --uid 10001 lab
WORKDIR /app
COPY server.py index.html lua_runner.lua ./
COPY pipelines ./pipelines
RUN mkdir -p /app/output /data && chown -R lab:lab /app /data
USER lab

ENV HOST=0.0.0.0 PORT=8790 IN_DOCKER=1 PYTHONUNBUFFERED=1
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python3 -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/api/status' % os.environ.get('PORT','8790'), timeout=4)" || exit 1
CMD ["python3", "server.py"]

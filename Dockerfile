FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SKILLCRED_DATA_DIR=/var/lib/skillcred

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY skillcred ./skillcred
COPY docker-entrypoint.sh /usr/local/bin/skillcred-entrypoint

RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux \
    && python -m pip install --upgrade pip \
    && python -m pip install . \
    && useradd --system --create-home --home-dir /home/skillcred skillcred \
    && mkdir -p /var/lib/skillcred \
    && chown -R skillcred:skillcred /app /var/lib/skillcred \
    && chmod 0755 /usr/local/bin/skillcred-entrypoint \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000
VOLUME ["/var/lib/skillcred"]
ENTRYPOINT ["/usr/local/bin/skillcred-entrypoint"]

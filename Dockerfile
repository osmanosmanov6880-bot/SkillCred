FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SKILLCRED_DATA_DIR=/var/lib/skillcred

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY skillcred ./skillcred
RUN python -m pip install --upgrade pip && python -m pip install . \
    && useradd --system --create-home --home-dir /home/skillcred skillcred \
    && mkdir -p /var/lib/skillcred \
    && chown -R skillcred:skillcred /app /var/lib/skillcred

USER skillcred
EXPOSE 8000
VOLUME ["/var/lib/skillcred"]
CMD ["uvicorn", "skillcred.api:app", "--host", "0.0.0.0", "--port", "8000"]

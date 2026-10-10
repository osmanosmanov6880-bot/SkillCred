FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --system --create-home --home-dir /home/conformance conformance
WORKDIR /work
COPY pyproject.toml README.md LICENSE ./
COPY skillcred ./skillcred
COPY schemas ./schemas
COPY scripts/fetch_official_schemas.py ./scripts/fetch_official_schemas.py
RUN python -m pip install --upgrade pip && python -m pip install '.[dev]'
USER conformance
ENTRYPOINT ["python", "-m", "pytest"]

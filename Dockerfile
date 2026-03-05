FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY guard_intent /app/guard_intent
COPY config.yaml /app/config.yaml
COPY data /app/data

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

ENTRYPOINT ["guardintent"]
CMD ["--help"]


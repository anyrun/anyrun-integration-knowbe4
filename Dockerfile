FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system connector && adduser --system --ingroup connector connector

COPY pyproject.toml ./
RUN pip install .

COPY ./src /app

RUN mkdir -p /app/logs && chown -R connector:connector /app

USER connector

CMD ["python", "main.py"]

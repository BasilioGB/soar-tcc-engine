FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
PYTHONUNBUFFERED=1 \
PIP_NO_CACHE_DIR=1


WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libcairo2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/
RUN pip install -r requirements.txt
COPY . /app


CMD ["bash", "-lc", "python manage.py migrate && python manage.py collectstatic --noinput && daphne -b 0.0.0.0 -p 8000 core.asgi:application"]

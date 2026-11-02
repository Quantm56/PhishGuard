# PhishGuard app Dockerfile
# Used by docker-compose.yml 'app' service.
# The main Flask API server.

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

RUN useradd -m -u 1000 appuser
USER appuser

EXPOSE 5000
CMD ["python", "api.py"]


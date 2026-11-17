FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py manage.py ./
COPY templates ./templates
COPY static ./static
# HTTPS com o certificado emitido pela CA do projeto (pki.py).
# O usuário (não root) é definido no docker-compose.
CMD ["gunicorn", "--bind", "0.0.0.0:8443", "--workers", "2", \
     "--certfile", "/certs/painel.crt", "--keyfile", "/certs/painel.key", \
     "--access-logfile", "-", "--access-logformat", "%(t)s painel_http ip=%(h)s \"%(r)s\" status=%(s)s", \
     "app:app"]

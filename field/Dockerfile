FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY device_sim.py .
# O usuário (não root) é definido no docker-compose (HOST_UID:HOST_GID),
# para conseguir ler a chave privada montada com permissão 0600.
CMD ["python", "device_sim.py"]

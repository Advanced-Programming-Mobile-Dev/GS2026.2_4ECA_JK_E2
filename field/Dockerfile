FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY field_sim.py devices.json ./
# O usuário (não root) é definido no docker-compose (HOST_UID:HOST_GID).
CMD ["python", "field_sim.py"]

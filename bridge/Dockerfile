FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 TZ=UTC
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY wokwi_bridge.py .
CMD ["python", "wokwi_bridge.py"]

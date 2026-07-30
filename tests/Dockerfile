FROM python:3-alpine
COPY fwtest /app/fwtest
COPY container_probe.py /app/
ENTRYPOINT ["python3", "/app/container_probe.py"]

# Built and exported on GitHub only. The deployed image ID is part of the
# private rollout receipt; this helper never builds or installs another image.
FROM python:3.12.7-alpine
RUN apk add --no-cache docker-cli && pip install --no-cache-dir paho-mqtt==2.1.0
WORKDIR /opt/p7u
COPY *.py SOURCE_SHA ./
ENTRYPOINT ["python", "-u", "/opt/p7u/p7u_lifecycle_main.py"]

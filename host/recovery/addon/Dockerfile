FROM python:3.12-alpine
ARG BUILD_VERSION=0.2.4
ARG BUILD_ARCH=aarch64
ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.revision="${SOURCE_SHA}"
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="${BUILD_ARCH}"
RUN apk add --no-cache tzdata && pip install --no-cache-dir "paho-mqtt==2.1.0" "PyYAML==6.0.2"
COPY policy.py executor.py persistence.py ha_adapter.py observer.py mqtt_settings.py alerts.py forensics.py run.py /app/
WORKDIR /app
ENV PYTHONUNBUFFERED=1 TZ=Europe/Prague
CMD ["python", "-u", "/app/run.py"]

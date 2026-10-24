# Separate HOST-PID observer. No S6: S6 requires PID 1 and fails
# in an HAOS host_pid namespace. No UART/devices mapping or network control.
FROM python:3.12.7-alpine
RUN apk add --no-cache docker-cli
WORKDIR /opt/p7u
COPY p7u_lifecycle_core.py p7u_ha_readonly_inspector.py p7u_owner_inspector_main.py ./
# No Supervisor POST in this image. Docker socket is used for inspect/top only.
ENTRYPOINT ["python", "-u", "/opt/p7u/p7u_owner_inspector_main.py"]

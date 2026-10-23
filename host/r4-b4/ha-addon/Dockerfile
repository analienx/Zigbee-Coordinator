# Supervisor uses docker buildx --pull: a local image tag is NOT a valid FROM.
# Rebuild the exact compiled candidate from the published digest-pinned image.
# All COPY sources MUST be extracted and SHA-verified from the green GitHub
# build artifact for the exact candidate source SHA,
# never generated directly on the HA host.
FROM ghcr.io/zigbee2mqtt/zigbee2mqtt-aarch64@sha256:97246758dab5099113c5a46fcbc1b9a36968a0eb9fd95ce8df6e2868cc7f533f
LABEL io.hass.version="0.2.0" \
      io.hass.type="app" \
      io.hass.arch="aarch64"
COPY z2m-controller.js /app/dist/controller.js
COPY z2m-otaUpdate.js /app/dist/extension/otaUpdate.js
COPY herdsman-dist/ /app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/
COPY p7u_diagnostic_worker.cjs /app/dist/p7u_diagnostic_worker.cjs

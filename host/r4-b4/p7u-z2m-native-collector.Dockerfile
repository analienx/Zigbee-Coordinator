# Exact installed production image digest, read-only attested 2026-10-22.
# Compile on GitHub-hosted runners only, never modify the live official image.
FROM ghcr.io/zigbee2mqtt/zigbee2mqtt-aarch64@sha256:97246758dab5099113c5a46fcbc1b9a36968a0eb9fd95ce8df6e2868cc7f533f AS patched
LABEL io.hass.version="0.2.0" \
      io.hass.type="app" \
      io.hass.arch="aarch64"
# Preserve vendor entrypoint, port, volume, user and all existing package files.
COPY z2m-controller.js /app/dist/controller.js
COPY z2m-otaUpdate.js /app/dist/extension/otaUpdate.js
# Copy the compiled pinned herdsman tree to the REAL pnpm target, not to
# /app/node_modules/zigbee-herdsman (which is a symlink).
COPY herdsman-dist/ /app/node_modules/.pnpm/zigbee-herdsman@10.9.1/node_modules/zigbee-herdsman/dist/

# Diagnostic history writer is no-serial and runs exclusively off the Z2M event loop.
COPY p7u_diagnostic_worker.cjs p7u_host_timeout_sink.cjs p7u_preservation_probe.cjs P7U_SOURCE_SHA.txt /app/dist/

FROM patched AS preservation
ENTRYPOINT ["node", "/app/dist/p7u_preservation_probe.cjs"]
CMD []

# Keep the ordinary diagnostic role as the DEFAULT build target.
FROM patched AS diagnostic

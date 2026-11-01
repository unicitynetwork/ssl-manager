# Test backend for the PROXY protocol e2e. BASE is the ssl-manager image under test.
ARG BASE=ssl-manager:latest
FROM ${BASE}
COPY app.py /app.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

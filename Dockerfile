FROM python:3.11-slim

LABEL org.opencontainers.image.title="README Injection Scan"
LABEL org.opencontainers.image.description="Scan documentation for invisible prompt injection patterns"
LABEL org.opencontainers.image.source="https://github.com/bountyyfi/invisible-prompt-injection"
LABEL org.opencontainers.image.authors="Bountyy Oy <info@bountyy.fi>"
LABEL org.opencontainers.image.licenses="MIT"

COPY injection_scan.py /usr/local/bin/injection_scan.py
RUN chmod +x /usr/local/bin/injection_scan.py

WORKDIR /workspace

# Reads SCAN_PATH, SCAN_RECURSIVE, SCAN_FAIL_ON, SCAN_EXCLUDE, SCAN_VERBOSE,
# SCAN_FORMAT from environment — no wrapper script needed.
ENTRYPOINT ["python3", "/usr/local/bin/injection_scan.py"]
CMD ["."]

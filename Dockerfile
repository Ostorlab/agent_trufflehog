FROM golang:1.26-alpine as scanner
RUN mkdir /install
WORKDIR /install
RUN apk add git
# Pinned to release v3.99.8 (ea68ca03c865, 2026-11-02) so the detector set is
# a deliberate, reproducible choice: images built before upstream commit
# 43b8e371aa (2026-08-11, "Update regex pattern and 403 handling in the Lob
# detector to fix false positives") carry the old Lob detector, which reports
# any exactly-35-char [a-zA-Z0-9_] identifier after live_/test_ (pytest names,
# Android resource names) as a Verified Lob key. Future detector updates are
# explicit tag bumps.
RUN git clone --branch v3.99.8 --depth 1 https://github.com/trufflesecurity/trufflehog.git trufflehog
RUN cd trufflehog ; go build -o trufflehog

FROM python:3.14-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --upgrade pip
RUN pip install --prefix=/install -r /requirement.txt

FROM base
COPY --from=builder /install /usr/local
COPY --from=scanner /install/trufflehog/trufflehog /usr/local/bin/trufflehog
# Trufflehog agent uses git for the GitHub repo scanning.
RUN apk add git
RUN apk add libmagic
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python", "/app/agent/trufflehog_agent.py"]

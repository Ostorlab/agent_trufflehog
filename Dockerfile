FROM golang:1.26-alpine as scanner
RUN mkdir /install
WORKDIR /install
RUN apk add git
# Pin the trufflehog checkout to a released tag so the detector set is a
# deliberate, reproducible choice rather than a function of image build date.
# v3.99.8 (ea68ca03c865) carries the 2026-08-11 Lob-detector fix that stops
# exactly-35-char [a-zA-Z0-9_] identifiers (pytest names such as
# test_<35 chars>) being matched, 403-verified and reported as live Lob keys;
# unpinned-main images built before that commit emit those as high-rated
# findings. Bump the tag deliberately; keep it at or above that fix.
# The tag-bounded shallow clone is deterministic for a given tag and keeps
# the build network transfer small.
RUN git clone --branch v3.99.8 --depth 1 \
        https://github.com/trufflesecurity/trufflehog.git trufflehog
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

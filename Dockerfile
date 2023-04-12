FROM golang:1.20-alpine as scanner
RUN mkdir /install
WORKDIR /install
RUN apk add git
RUN git clone https://github.com/trufflesecurity/trufflehog.git trufflehog 
RUN cd trufflehog ; go build -o trufflehog

FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt

FROM base
COPY --from=builder /install /usr/local
COPY --from=scanner /install/trufflehog/trufflehog /usr/local/bin/trufflehog
# trufflehog agent uses git for the github repo option
RUN apk add git
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/trufflehog_agent.py"]

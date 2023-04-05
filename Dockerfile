FROM python:3.10-alpine as base
FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
RUN apk add git
RUN git clone https://github.com/trufflesecurity/trufflehog.git trufflehog
COPY --from=golang:1.20-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
RUN cd /install/trufflehog ; go install

FROM base
COPY --from=builder /install /usr/local
COPY --from=builder /root/go/bin/trufflehog /usr/local/bin/trufflehog
RUN mkdir -p /app/agent
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/trufflehog_agent.py"]

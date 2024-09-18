FROM golang:1.22

RUN apt-get update && apt-get install -y \
    curl \
    tar \
    git \
    make \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="${PATH}:/root/.foundry/bin"
RUN foundryup

WORKDIR /go/astraeus-api-node
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN chmod 755 ./scripts/docker/*.sh

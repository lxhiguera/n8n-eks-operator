# Multi-stage build for n8n backup container
FROM postgres:15-alpine AS postgres-tools

# Install additional tools
RUN apk add --no-cache \
    aws-cli \
    curl \
    jq \
    tar \
    gzip \
    bash

FROM alpine:3.18 AS kubectl-installer

# Install kubectl
RUN apk add --no-cache curl && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

FROM postgres-tools

# Copy kubectl from installer stage
COPY --from=kubectl-installer /usr/local/bin/kubectl /usr/local/bin/kubectl

# Create backup user
RUN addgroup -g 1000 backup && \
    adduser -D -u 1000 -G backup backup

# Create directories
RUN mkdir -p /opt/backup /tmp/backup && \
    chown -R backup:backup /opt/backup /tmp/backup

# Copy backup scripts
COPY scripts/ /opt/backup/scripts/
RUN chmod +x /opt/backup/scripts/*.sh && \
    chown -R backup:backup /opt/backup/scripts/

# Set working directory
WORKDIR /opt/backup

# Switch to backup user
USER backup

# Set entrypoint
ENTRYPOINT ["/opt/backup/scripts/backup.sh"]
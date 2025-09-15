# Multi-stage build for n8n restore container
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

# Create restore user
RUN addgroup -g 1000 restore && \
    adduser -D -u 1000 -G restore restore

# Create directories
RUN mkdir -p /opt/restore /tmp/restore && \
    chown -R restore:restore /opt/restore /tmp/restore

# Copy restore scripts
COPY scripts/ /opt/restore/scripts/
RUN chmod +x /opt/restore/scripts/*.sh && \
    chown -R restore:restore /opt/restore/scripts/

# Set working directory
WORKDIR /opt/restore

# Switch to restore user
USER restore

# Set entrypoint
ENTRYPOINT ["/opt/restore/scripts/restore.sh"]
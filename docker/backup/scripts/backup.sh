#!/bin/bash

set -euo pipefail

# Configuration
BACKUP_TYPE="${BACKUP_TYPE:-full}"
INSTANCE_NAME="${INSTANCE_NAME:-}"
INSTANCE_NAMESPACE="${INSTANCE_NAMESPACE:-default}"
BACKUP_DIR="/tmp/backup-$(date +%Y%m%d-%H%M%S)"
CONFIG_FILE="/etc/backup/backup.yaml"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Error handling
error_exit() {
    log "ERROR: $1"
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    rm -rf "$BACKUP_DIR" 2>/dev/null || true
}

# Trap for cleanup on exit
trap cleanup EXIT

# Validate required environment variables
validate_environment() {
    log "Validating environment..."
    
    if [[ -z "$INSTANCE_NAME" ]]; then
        error_exit "INSTANCE_NAME environment variable is required"
    fi
    
    if [[ -z "$INSTANCE_NAMESPACE" ]]; then
        error_exit "INSTANCE_NAMESPACE environment variable is required"
    fi
    
    # Check if config file exists
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "Configuration file not found: $CONFIG_FILE"
    fi
    
    log "Environment validation completed"
}

# Load configuration from YAML file
load_config() {
    log "Loading configuration from $CONFIG_FILE..."
    
    # Parse YAML configuration (simplified parsing)
    eval $(grep -E '^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*:' "$CONFIG_FILE" | \
           sed 's/:[[:space:]]*/=/' | \
           sed 's/^[[:space:]]*//' | \
           sed 's/"//g' | \
           tr '.' '_')
    
    log "Configuration loaded successfully"
}

# Create backup directory
create_backup_directory() {
    log "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Create subdirectories
    mkdir -p "$BACKUP_DIR/database"
    mkdir -p "$BACKUP_DIR/workflows"
    mkdir -p "$BACKUP_DIR/secrets"
    mkdir -p "$BACKUP_DIR/metadata"
}

# Generate backup metadata
generate_metadata() {
    log "Generating backup metadata..."
    
    cat > "$BACKUP_DIR/metadata/backup.json" << EOF
{
    "backupId": "$(basename $BACKUP_DIR)",
    "type": "$BACKUP_TYPE",
    "instance": {
        "name": "$INSTANCE_NAME",
        "namespace": "$INSTANCE_NAMESPACE"
    },
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "version": "1.0.0",
    "components": []
}
EOF
}

# Database backup function
backup_database() {
    log "Starting database backup..."
    
    # Check if database credentials are available
    if [[ -z "${DATABASE_HOST:-}" ]] || [[ -z "${DATABASE_NAME:-}" ]]; then
        log "Database configuration not found, skipping database backup"
        return 0
    fi
    
    # Set database connection parameters
    export PGHOST="${DATABASE_HOST}"
    export PGPORT="${DATABASE_PORT:-5432}"
    export PGDATABASE="${DATABASE_NAME}"
    export PGUSER="${DATABASE_USER:-n8n}"
    
    # Get password from secret if available
    if [[ -n "${DATABASE_PASSWORD_FILE:-}" ]] && [[ -f "$DATABASE_PASSWORD_FILE" ]]; then
        export PGPASSWORD="$(cat $DATABASE_PASSWORD_FILE)"
    elif [[ -n "${DATABASE_PASSWORD:-}" ]]; then
        export PGPASSWORD="$DATABASE_PASSWORD"
    fi
    
    # Test database connection
    log "Testing database connection..."
    if ! pg_isready -q; then
        error_exit "Cannot connect to database"
    fi
    
    # Create database dump
    log "Creating database dump..."
    pg_dump \
        --verbose \
        --format=custom \
        --compress=9 \
        --no-privileges \
        --no-owner \
        --file="$BACKUP_DIR/database/n8n.dump"
    
    # Create schema-only dump for faster restores
    pg_dump \
        --verbose \
        --schema-only \
        --format=plain \
        --file="$BACKUP_DIR/database/schema.sql"
    
    # Get database statistics
    psql -c "SELECT 
        schemaname,
        tablename,
        n_tup_ins as inserts,
        n_tup_upd as updates,
        n_tup_del as deletes,
        n_live_tup as live_tuples,
        n_dead_tup as dead_tuples
    FROM pg_stat_user_tables;" \
    --csv > "$BACKUP_DIR/database/statistics.csv"
    
    log "Database backup completed"
    
    # Update metadata
    jq '.components += ["database"]' "$BACKUP_DIR/metadata/backup.json" > "$BACKUP_DIR/metadata/backup.json.tmp"
    mv "$BACKUP_DIR/metadata/backup.json.tmp" "$BACKUP_DIR/metadata/backup.json"
}

# Workflows backup function
backup_workflows() {
    log "Starting workflows backup..."
    
    if [[ -z "${STORAGE_S3_BUCKET:-}" ]]; then
        log "S3 storage configuration not found, skipping workflows backup"
        return 0
    fi
    
    # Sync workflows from S3
    log "Syncing workflows from S3..."
    aws s3 sync "s3://$STORAGE_S3_BUCKET" "$BACKUP_DIR/workflows" \
        --exclude "*" \
        --include "workflows/*" \
        --include "credentials/*" \
        --include "variables/*"
    
    # Create workflows archive
    log "Creating workflows archive..."
    if [[ -d "$BACKUP_DIR/workflows" ]] && [[ "$(ls -A $BACKUP_DIR/workflows)" ]]; then
        tar -czf "$BACKUP_DIR/workflows.tar.gz" -C "$BACKUP_DIR" workflows/
        rm -rf "$BACKUP_DIR/workflows"
        
        # Get archive size
        WORKFLOWS_SIZE=$(stat -c%s "$BACKUP_DIR/workflows.tar.gz")
        log "Workflows archive created: ${WORKFLOWS_SIZE} bytes"
    else
        log "No workflows found to backup"
        touch "$BACKUP_DIR/workflows.empty"
    fi
    
    log "Workflows backup completed"
    
    # Update metadata
    jq '.components += ["workflows"]' "$BACKUP_DIR/metadata/backup.json" > "$BACKUP_DIR/metadata/backup.json.tmp"
    mv "$BACKUP_DIR/metadata/backup.json.tmp" "$BACKUP_DIR/metadata/backup.json"
}

# Secrets backup function
backup_secrets() {
    log "Starting secrets backup..."
    
    # Get all secrets in the namespace
    log "Exporting Kubernetes secrets..."
    kubectl get secrets -n "$INSTANCE_NAMESPACE" \
        -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        -o json > "$BACKUP_DIR/secrets/secrets.json"
    
    # Filter out system secrets and encode sensitive data
    jq '.items[] | select(.type != "kubernetes.io/service-account-token") | {
        apiVersion: .apiVersion,
        kind: .kind,
        metadata: {
            name: .metadata.name,
            namespace: .metadata.namespace,
            labels: .metadata.labels,
            annotations: .metadata.annotations
        },
        type: .type,
        data: .data
    }' "$BACKUP_DIR/secrets/secrets.json" > "$BACKUP_DIR/secrets/filtered-secrets.json"
    
    # Create secrets summary
    jq -r '.items[] | "\(.metadata.name),\(.type),\(.data | keys | length)"' \
        "$BACKUP_DIR/secrets/secrets.json" > "$BACKUP_DIR/secrets/summary.csv"
    
    log "Secrets backup completed"
    
    # Update metadata
    jq '.components += ["secrets"]' "$BACKUP_DIR/metadata/backup.json" > "$BACKUP_DIR/metadata/backup.json.tmp"
    mv "$BACKUP_DIR/metadata/backup.json.tmp" "$BACKUP_DIR/metadata/backup.json"
}

# Configuration backup function
backup_configuration() {
    log "Starting configuration backup..."
    
    # Get ConfigMaps
    kubectl get configmaps -n "$INSTANCE_NAMESPACE" \
        -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        -o json > "$BACKUP_DIR/metadata/configmaps.json"
    
    # Get N8nInstance resource
    kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o json > "$BACKUP_DIR/metadata/n8ninstance.json"
    
    # Get related resources
    kubectl get all -n "$INSTANCE_NAMESPACE" \
        -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        -o json > "$BACKUP_DIR/metadata/resources.json"
    
    log "Configuration backup completed"
    
    # Update metadata
    jq '.components += ["configuration"]' "$BACKUP_DIR/metadata/backup.json" > "$BACKUP_DIR/metadata/backup.json.tmp"
    mv "$BACKUP_DIR/metadata/backup.json.tmp" "$BACKUP_DIR/metadata/backup.json"
}

# Create backup archive
create_backup_archive() {
    log "Creating backup archive..."
    
    ARCHIVE_NAME="$(basename $BACKUP_DIR).tar.gz"
    ARCHIVE_PATH="/tmp/$ARCHIVE_NAME"
    
    # Create compressed archive
    tar -czf "$ARCHIVE_PATH" -C "/tmp" "$(basename $BACKUP_DIR)"
    
    # Calculate checksum
    CHECKSUM=$(sha256sum "$ARCHIVE_PATH" | cut -d' ' -f1)
    echo "$CHECKSUM" > "$ARCHIVE_PATH.sha256"
    
    # Get archive size
    ARCHIVE_SIZE=$(stat -c%s "$ARCHIVE_PATH")
    
    log "Backup archive created: $ARCHIVE_PATH ($ARCHIVE_SIZE bytes, checksum: $CHECKSUM)"
    
    # Update metadata with archive info
    jq --arg size "$ARCHIVE_SIZE" --arg checksum "$CHECKSUM" \
        '.size = ($size | tonumber) | .checksum = $checksum' \
        "$BACKUP_DIR/metadata/backup.json" > "$BACKUP_DIR/metadata/backup.json.tmp"
    mv "$BACKUP_DIR/metadata/backup.json.tmp" "$BACKUP_DIR/metadata/backup.json"
    
    echo "$ARCHIVE_PATH"
}

# Upload backup to S3
upload_backup() {
    local archive_path="$1"
    
    log "Uploading backup to S3..."
    
    if [[ -z "${S3_BUCKET:-}" ]]; then
        error_exit "S3_BUCKET not configured"
    fi
    
    # Construct S3 key
    S3_KEY="${S3_PREFIX:-backups}/$INSTANCE_NAMESPACE/$INSTANCE_NAME/$(basename $archive_path)"
    
    # Upload archive
    aws s3 cp "$archive_path" "s3://$S3_BUCKET/$S3_KEY" \
        --storage-class STANDARD_IA \
        --metadata "instance=$INSTANCE_NAME,namespace=$INSTANCE_NAMESPACE,type=$BACKUP_TYPE"
    
    # Upload checksum
    aws s3 cp "$archive_path.sha256" "s3://$S3_BUCKET/$S3_KEY.sha256"
    
    # Upload metadata
    aws s3 cp "$BACKUP_DIR/metadata/backup.json" "s3://$S3_BUCKET/$S3_KEY.metadata.json"
    
    log "Backup uploaded successfully: s3://$S3_BUCKET/$S3_KEY"
    
    # Set lifecycle policy if configured
    if [[ -n "${LIFECYCLE_DAYS:-}" ]]; then
        aws s3api put-object-tagging \
            --bucket "$S3_BUCKET" \
            --key "$S3_KEY" \
            --tagging "TagSet=[{Key=Lifecycle,Value=$LIFECYCLE_DAYS}]"
    fi
}

# Verify backup integrity
verify_backup() {
    local archive_path="$1"
    
    log "Verifying backup integrity..."
    
    # Verify checksum
    if ! sha256sum -c "$archive_path.sha256"; then
        error_exit "Backup checksum verification failed"
    fi
    
    # Test archive integrity
    if ! tar -tzf "$archive_path" >/dev/null; then
        error_exit "Backup archive integrity check failed"
    fi
    
    log "Backup integrity verification passed"
}

# Send notification
send_notification() {
    local status="$1"
    local message="$2"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        curl -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"instance\": \"$INSTANCE_NAME\",
                \"namespace\": \"$INSTANCE_NAMESPACE\",
                \"type\": \"$BACKUP_TYPE\",
                \"status\": \"$status\",
                \"message\": \"$message\",
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }" || log "Failed to send notification"
    fi
}

# Main backup function
main() {
    log "Starting n8n backup process"
    log "Backup type: $BACKUP_TYPE"
    log "Instance: $INSTANCE_NAME (namespace: $INSTANCE_NAMESPACE)"
    
    # Validate environment and load configuration
    validate_environment
    load_config
    
    # Create backup directory and metadata
    create_backup_directory
    generate_metadata
    
    # Perform backup based on type
    case "$BACKUP_TYPE" in
        "full")
            backup_database
            backup_workflows
            backup_secrets
            backup_configuration
            ;;
        "database")
            backup_database
            ;;
        "workflows")
            backup_workflows
            ;;
        "secrets")
            backup_secrets
            ;;
        "configuration")
            backup_configuration
            ;;
        *)
            error_exit "Unknown backup type: $BACKUP_TYPE"
            ;;
    esac
    
    # Create and upload backup archive
    archive_path=$(create_backup_archive)
    verify_backup "$archive_path"
    upload_backup "$archive_path"
    
    # Send success notification
    send_notification "success" "Backup completed successfully"
    
    log "Backup process completed successfully"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
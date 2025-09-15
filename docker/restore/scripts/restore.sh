#!/bin/bash

set -euo pipefail

# Configuration
BACKUP_LOCATION="${BACKUP_LOCATION:-}"
BACKUP_TYPE="${BACKUP_TYPE:-full}"
INSTANCE_NAME="${INSTANCE_NAME:-}"
INSTANCE_NAMESPACE="${INSTANCE_NAMESPACE:-default}"
RESTORE_DIR="/tmp/restore-$(date +%Y%m%d-%H%M%S)"
DRY_RUN="${DRY_RUN:-false}"

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
    rm -rf "$RESTORE_DIR" 2>/dev/null || true
}

# Trap for cleanup on exit
trap cleanup EXIT

# Validate required environment variables
validate_environment() {
    log "Validating environment..."
    
    if [[ -z "$BACKUP_LOCATION" ]]; then
        error_exit "BACKUP_LOCATION environment variable is required"
    fi
    
    if [[ -z "$INSTANCE_NAME" ]]; then
        error_exit "INSTANCE_NAME environment variable is required"
    fi
    
    if [[ -z "$INSTANCE_NAMESPACE" ]]; then
        error_exit "INSTANCE_NAMESPACE environment variable is required"
    fi
    
    log "Environment validation completed"
}

# Download backup from S3
download_backup() {
    log "Downloading backup from: $BACKUP_LOCATION"
    
    # Parse S3 location
    if [[ ! "$BACKUP_LOCATION" =~ ^s3://([^/]+)/(.+)$ ]]; then
        error_exit "Invalid S3 location format: $BACKUP_LOCATION"
    fi
    
    local bucket="${BASH_REMATCH[1]}"
    local key="${BASH_REMATCH[2]}"
    local archive_name="$(basename $key)"
    local archive_path="$RESTORE_DIR/$archive_name"
    
    # Create restore directory
    mkdir -p "$RESTORE_DIR"
    
    # Download backup archive
    log "Downloading backup archive..."
    aws s3 cp "$BACKUP_LOCATION" "$archive_path"
    
    # Download checksum
    log "Downloading checksum..."
    aws s3 cp "$BACKUP_LOCATION.sha256" "$archive_path.sha256"
    
    # Download metadata
    log "Downloading metadata..."
    aws s3 cp "$BACKUP_LOCATION.metadata.json" "$RESTORE_DIR/backup.metadata.json" || {
        log "Warning: Metadata file not found, continuing without it"
    }
    
    echo "$archive_path"
}

# Verify backup integrity
verify_backup() {
    local archive_path="$1"
    
    log "Verifying backup integrity..."
    
    # Verify checksum
    if ! (cd "$(dirname $archive_path)" && sha256sum -c "$(basename $archive_path).sha256"); then
        error_exit "Backup checksum verification failed"
    fi
    
    # Test archive integrity
    if ! tar -tzf "$archive_path" >/dev/null; then
        error_exit "Backup archive integrity check failed"
    fi
    
    log "Backup integrity verification passed"
}

# Extract backup archive
extract_backup() {
    local archive_path="$1"
    
    log "Extracting backup archive..."
    
    # Extract archive
    tar -xzf "$archive_path" -C "$RESTORE_DIR"
    
    # Find extracted directory
    local extracted_dir=$(find "$RESTORE_DIR" -maxdepth 1 -type d -name "backup-*" | head -1)
    if [[ -z "$extracted_dir" ]]; then
        error_exit "Could not find extracted backup directory"
    fi
    
    log "Backup extracted to: $extracted_dir"
    echo "$extracted_dir"
}

# Load backup metadata
load_backup_metadata() {
    local backup_dir="$1"
    
    log "Loading backup metadata..."
    
    local metadata_file="$backup_dir/metadata/backup.json"
    if [[ ! -f "$metadata_file" ]]; then
        log "Warning: Backup metadata not found, using defaults"
        return
    fi
    
    # Parse metadata
    BACKUP_ID=$(jq -r '.backupId // empty' "$metadata_file")
    BACKUP_TIMESTAMP=$(jq -r '.timestamp // empty' "$metadata_file")
    BACKUP_COMPONENTS=$(jq -r '.components[]? // empty' "$metadata_file")
    ORIGINAL_INSTANCE=$(jq -r '.instance.name // empty' "$metadata_file")
    ORIGINAL_NAMESPACE=$(jq -r '.instance.namespace // empty' "$metadata_file")
    
    log "Backup ID: ${BACKUP_ID:-unknown}"
    log "Backup timestamp: ${BACKUP_TIMESTAMP:-unknown}"
    log "Original instance: ${ORIGINAL_INSTANCE:-unknown}"
    log "Original namespace: ${ORIGINAL_NAMESPACE:-unknown}"
    log "Components: ${BACKUP_COMPONENTS:-none}"
}

# Pre-restore validation
pre_restore_validation() {
    log "Performing pre-restore validation..."
    
    # Check if target instance exists
    if kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" >/dev/null 2>&1; then
        log "Target N8nInstance exists: $INSTANCE_NAME"
        
        # Check if instance is running
        local phase=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" -o jsonpath='{.status.phase}')
        if [[ "$phase" == "Ready" ]]; then
            log "Warning: Target instance is currently running. Consider stopping it before restore."
            if [[ "$DRY_RUN" != "true" ]]; then
                read -p "Continue with restore? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    error_exit "Restore cancelled by user"
                fi
            fi
        fi
    else
        log "Target N8nInstance does not exist, will need to be created after restore"
    fi
    
    # Check database connectivity
    if [[ -n "${DATABASE_HOST:-}" ]]; then
        log "Testing database connectivity..."
        export PGHOST="${DATABASE_HOST}"
        export PGPORT="${DATABASE_PORT:-5432}"
        export PGDATABASE="${DATABASE_NAME:-n8n}"
        export PGUSER="${DATABASE_USER:-n8n}"
        
        if [[ -n "${DATABASE_PASSWORD_FILE:-}" ]] && [[ -f "$DATABASE_PASSWORD_FILE" ]]; then
            export PGPASSWORD="$(cat $DATABASE_PASSWORD_FILE)"
        elif [[ -n "${DATABASE_PASSWORD:-}" ]]; then
            export PGPASSWORD="$DATABASE_PASSWORD"
        fi
        
        if ! pg_isready -q; then
            error_exit "Cannot connect to target database"
        fi
        log "Database connectivity verified"
    fi
    
    log "Pre-restore validation completed"
}

# Restore database
restore_database() {
    local backup_dir="$1"
    
    log "Starting database restore..."
    
    local db_backup_file="$backup_dir/database/n8n.dump"
    if [[ ! -f "$db_backup_file" ]]; then
        log "Database backup file not found, skipping database restore"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restore database from $db_backup_file"
        return 0
    fi
    
    # Create backup of current database
    log "Creating backup of current database..."
    local current_backup="/tmp/current-db-backup-$(date +%Y%m%d-%H%M%S).dump"
    pg_dump --format=custom --file="$current_backup" || {
        log "Warning: Could not create backup of current database"
    }
    
    # Drop existing connections
    log "Terminating existing database connections..."
    psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$PGDATABASE' AND pid <> pg_backend_pid();" || true
    
    # Restore database
    log "Restoring database..."
    pg_restore \
        --verbose \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        --dbname="$PGDATABASE" \
        "$db_backup_file"
    
    # Verify restore
    log "Verifying database restore..."
    local table_count=$(psql -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')
    log "Restored $table_count tables"
    
    # Update database statistics
    log "Updating database statistics..."
    psql -c "ANALYZE;"
    
    log "Database restore completed"
}

# Restore workflows
restore_workflows() {
    local backup_dir="$1"
    
    log "Starting workflows restore..."
    
    local workflows_archive="$backup_dir/workflows.tar.gz"
    if [[ ! -f "$workflows_archive" ]]; then
        if [[ -f "$backup_dir/workflows.empty" ]]; then
            log "No workflows to restore (empty backup)"
            return 0
        fi
        log "Workflows backup file not found, skipping workflows restore"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restore workflows from $workflows_archive"
        return 0
    fi
    
    # Extract workflows
    log "Extracting workflows..."
    local temp_workflows_dir="/tmp/workflows-restore"
    mkdir -p "$temp_workflows_dir"
    tar -xzf "$workflows_archive" -C "$temp_workflows_dir"
    
    # Upload to S3
    if [[ -n "${STORAGE_S3_BUCKET:-}" ]]; then
        log "Uploading workflows to S3..."
        aws s3 sync "$temp_workflows_dir/workflows" "s3://$STORAGE_S3_BUCKET" \
            --delete \
            --exclude "*.tmp" \
            --exclude "*.lock"
        
        log "Workflows uploaded to S3 successfully"
    else
        log "Warning: S3 storage not configured, workflows not uploaded"
    fi
    
    # Cleanup
    rm -rf "$temp_workflows_dir"
    
    log "Workflows restore completed"
}

# Restore secrets
restore_secrets() {
    local backup_dir="$1"
    
    log "Starting secrets restore..."
    
    local secrets_file="$backup_dir/secrets/filtered-secrets.json"
    if [[ ! -f "$secrets_file" ]]; then
        log "Secrets backup file not found, skipping secrets restore"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restore secrets from $secrets_file"
        return 0
    fi
    
    # Process each secret
    log "Processing secrets..."
    local secret_count=0
    
    while IFS= read -r secret; do
        if [[ -z "$secret" ]] || [[ "$secret" == "null" ]]; then
            continue
        fi
        
        local secret_name=$(echo "$secret" | jq -r '.metadata.name')
        local secret_namespace=$(echo "$secret" | jq -r '.metadata.namespace')
        
        # Update namespace if different
        if [[ "$secret_namespace" != "$INSTANCE_NAMESPACE" ]]; then
            secret=$(echo "$secret" | jq --arg ns "$INSTANCE_NAMESPACE" '.metadata.namespace = $ns')
        fi
        
        # Apply secret
        echo "$secret" | kubectl apply -f - || {
            log "Warning: Failed to restore secret: $secret_name"
            continue
        }
        
        ((secret_count++))
        log "Restored secret: $secret_name"
        
    done < <(jq -c '.[]?' "$secrets_file" 2>/dev/null || jq -c '.' "$secrets_file")
    
    log "Secrets restore completed: $secret_count secrets restored"
}

# Restore configuration
restore_configuration() {
    local backup_dir="$1"
    
    log "Starting configuration restore..."
    
    local configmaps_file="$backup_dir/metadata/configmaps.json"
    local n8ninstance_file="$backup_dir/metadata/n8ninstance.json"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would restore configuration"
        return 0
    fi
    
    # Restore ConfigMaps
    if [[ -f "$configmaps_file" ]]; then
        log "Restoring ConfigMaps..."
        local configmap_count=0
        
        while IFS= read -r configmap; do
            if [[ -z "$configmap" ]] || [[ "$configmap" == "null" ]]; then
                continue
            fi
            
            local cm_name=$(echo "$configmap" | jq -r '.metadata.name')
            local cm_namespace=$(echo "$configmap" | jq -r '.metadata.namespace')
            
            # Update namespace if different
            if [[ "$cm_namespace" != "$INSTANCE_NAMESPACE" ]]; then
                configmap=$(echo "$configmap" | jq --arg ns "$INSTANCE_NAMESPACE" '.metadata.namespace = $ns')
            fi
            
            # Remove system fields
            configmap=$(echo "$configmap" | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp)')
            
            # Apply ConfigMap
            echo "$configmap" | kubectl apply -f - || {
                log "Warning: Failed to restore ConfigMap: $cm_name"
                continue
            }
            
            ((configmap_count++))
            log "Restored ConfigMap: $cm_name"
            
        done < <(jq -c '.items[]?' "$configmaps_file" 2>/dev/null)
        
        log "ConfigMaps restore completed: $configmap_count ConfigMaps restored"
    fi
    
    # Restore N8nInstance (if it doesn't exist)
    if [[ -f "$n8ninstance_file" ]] && ! kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" >/dev/null 2>&1; then
        log "Restoring N8nInstance resource..."
        
        local n8ninstance=$(cat "$n8ninstance_file")
        
        # Update name and namespace
        n8ninstance=$(echo "$n8ninstance" | jq \
            --arg name "$INSTANCE_NAME" \
            --arg ns "$INSTANCE_NAMESPACE" \
            '.metadata.name = $name | .metadata.namespace = $ns')
        
        # Remove system fields
        n8ninstance=$(echo "$n8ninstance" | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .status)')
        
        # Apply N8nInstance
        echo "$n8ninstance" | kubectl apply -f - || {
            log "Warning: Failed to restore N8nInstance resource"
        }
        
        log "N8nInstance resource restored"
    fi
    
    log "Configuration restore completed"
}

# Post-restore validation
post_restore_validation() {
    log "Performing post-restore validation..."
    
    # Wait for instance to be ready
    if kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" >/dev/null 2>&1; then
        log "Waiting for N8nInstance to be ready..."
        kubectl wait --for=condition=Ready n8ninstance/"$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" --timeout=300s || {
            log "Warning: N8nInstance did not become ready within timeout"
        }
    fi
    
    # Validate database connectivity
    if [[ -n "${DATABASE_HOST:-}" ]]; then
        log "Validating database connectivity..."
        if pg_isready -q; then
            local table_count=$(psql -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')
            log "Database validation passed: $table_count tables found"
        else
            log "Warning: Database connectivity validation failed"
        fi
    fi
    
    # Validate workflows in S3
    if [[ -n "${STORAGE_S3_BUCKET:-}" ]]; then
        log "Validating workflows in S3..."
        local object_count=$(aws s3 ls "s3://$STORAGE_S3_BUCKET/workflows/" --recursive | wc -l)
        log "S3 validation passed: $object_count workflow objects found"
    fi
    
    log "Post-restore validation completed"
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
                \"backup_location\": \"$BACKUP_LOCATION\",
                \"type\": \"restore\",
                \"status\": \"$status\",
                \"message\": \"$message\",
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }" || log "Failed to send notification"
    fi
}

# Main restore function
main() {
    log "Starting n8n restore process"
    log "Backup location: $BACKUP_LOCATION"
    log "Backup type: $BACKUP_TYPE"
    log "Target instance: $INSTANCE_NAME (namespace: $INSTANCE_NAMESPACE)"
    log "Dry run: $DRY_RUN"
    
    # Validate environment
    validate_environment
    
    # Download and verify backup
    archive_path=$(download_backup)
    verify_backup "$archive_path"
    
    # Extract backup
    backup_dir=$(extract_backup "$archive_path")
    load_backup_metadata "$backup_dir"
    
    # Pre-restore validation
    pre_restore_validation
    
    # Perform restore based on type
    case "$BACKUP_TYPE" in
        "full")
            restore_database "$backup_dir"
            restore_workflows "$backup_dir"
            restore_secrets "$backup_dir"
            restore_configuration "$backup_dir"
            ;;
        "database")
            restore_database "$backup_dir"
            ;;
        "workflows")
            restore_workflows "$backup_dir"
            ;;
        "secrets")
            restore_secrets "$backup_dir"
            ;;
        "configuration")
            restore_configuration "$backup_dir"
            ;;
        *)
            error_exit "Unknown backup type: $BACKUP_TYPE"
            ;;
    esac
    
    # Post-restore validation
    if [[ "$DRY_RUN" != "true" ]]; then
        post_restore_validation
    fi
    
    # Send success notification
    local message="Restore completed successfully"
    if [[ "$DRY_RUN" == "true" ]]; then
        message="Dry run completed successfully"
    fi
    send_notification "success" "$message"
    
    log "Restore process completed successfully"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
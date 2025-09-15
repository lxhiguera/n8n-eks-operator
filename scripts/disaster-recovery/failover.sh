#!/bin/bash

set -euo pipefail

# Disaster Recovery Failover Script for n8n EKS Operator
# This script handles automated failover between AWS regions

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/failover.conf}"
LOG_FILE="${LOG_FILE:-/var/log/n8n-failover.log}"

# Default values
SOURCE_REGION="${SOURCE_REGION:-}"
TARGET_REGION="${TARGET_REGION:-}"
INSTANCE_NAME="${INSTANCE_NAME:-}"
INSTANCE_NAMESPACE="${INSTANCE_NAMESPACE:-n8n-production}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_FAILOVER="${FORCE_FAILOVER:-false}"
ROLLBACK="${ROLLBACK:-false}"
FAILOVER_ID="${FAILOVER_ID:-}"

# Timeouts and thresholds
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
DATABASE_PROMOTION_TIMEOUT="${DATABASE_PROMOTION_TIMEOUT:-600}"
DNS_PROPAGATION_TIMEOUT="${DNS_PROPAGATION_TIMEOUT:-300}"
APPLICATION_STARTUP_TIMEOUT="${APPLICATION_STARTUP_TIMEOUT:-600}"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" >&2
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    send_notification "failed" "Failover failed: $1"
    exit 1
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading configuration from $CONFIG_FILE"
        source "$CONFIG_FILE"
    else
        log "WARN" "Configuration file not found: $CONFIG_FILE"
    fi
}

# Validate environment
validate_environment() {
    log "INFO" "Validating environment..."
    
    # Check required tools
    for tool in aws kubectl jq; do
        if ! command -v "$tool" &> /dev/null; then
            error_exit "Required tool not found: $tool"
        fi
    done
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        error_exit "AWS credentials not configured or invalid"
    fi
    
    # Check kubectl access
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "kubectl not configured or cluster not accessible"
    fi
    
    # Validate required parameters
    if [[ -z "$INSTANCE_NAME" ]]; then
        error_exit "INSTANCE_NAME is required"
    fi
    
    if [[ "$ROLLBACK" != "true" ]]; then
        if [[ -z "$SOURCE_REGION" ]]; then
            error_exit "SOURCE_REGION is required for failover"
        fi
        
        if [[ -z "$TARGET_REGION" ]]; then
            error_exit "TARGET_REGION is required for failover"
        fi
        
        if [[ "$SOURCE_REGION" == "$TARGET_REGION" ]]; then
            error_exit "SOURCE_REGION and TARGET_REGION cannot be the same"
        fi
    else
        if [[ -z "$FAILOVER_ID" ]]; then
            error_exit "FAILOVER_ID is required for rollback"
        fi
    fi
    
    log "INFO" "Environment validation completed"
}

# Check failover prerequisites
check_prerequisites() {
    log "INFO" "Checking failover prerequisites..."
    
    # Check if N8nInstance exists
    if ! kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" &> /dev/null; then
        error_exit "N8nInstance '$INSTANCE_NAME' not found in namespace '$INSTANCE_NAMESPACE'"
    fi
    
    # Check if multi-region is enabled
    local multi_region_enabled=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.spec.multiRegion.enabled}' 2>/dev/null || echo "false")
    
    if [[ "$multi_region_enabled" != "true" ]]; then
        error_exit "Multi-region is not enabled for instance '$INSTANCE_NAME'"
    fi
    
    # Check target region configuration
    local target_region_configured=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath="{.spec.multiRegion.regions[?(@.name=='$TARGET_REGION')].enabled}" 2>/dev/null || echo "false")
    
    if [[ "$target_region_configured" != "true" ]]; then
        error_exit "Target region '$TARGET_REGION' is not configured or enabled"
    fi
    
    log "INFO" "Prerequisites check completed"
}

# Check region health
check_region_health() {
    local region="$1"
    local check_type="${2:-full}"
    
    log "INFO" "Checking health of region: $region"
    
    # Check database health
    if [[ "$check_type" == "full" ]] || [[ "$check_type" == "database" ]]; then
        log "INFO" "Checking database health in $region..."
        
        local db_endpoint=$(get_database_endpoint "$region")
        if [[ -n "$db_endpoint" ]]; then
            if ! check_database_connectivity "$db_endpoint" "$region"; then
                log "ERROR" "Database health check failed for region $region"
                return 1
            fi
        else
            log "WARN" "No database endpoint found for region $region"
        fi
    fi
    
    # Check storage health
    if [[ "$check_type" == "full" ]] || [[ "$check_type" == "storage" ]]; then
        log "INFO" "Checking storage health in $region..."
        
        local storage_bucket=$(get_storage_bucket "$region")
        if [[ -n "$storage_bucket" ]]; then
            if ! check_storage_accessibility "$storage_bucket" "$region"; then
                log "ERROR" "Storage health check failed for region $region"
                return 1
            fi
        else
            log "WARN" "No storage bucket found for region $region"
        fi
    fi
    
    # Check application health
    if [[ "$check_type" == "full" ]] || [[ "$check_type" == "application" ]]; then
        log "INFO" "Checking application health in $region..."
        
        local app_endpoint=$(get_application_endpoint "$region")
        if [[ -n "$app_endpoint" ]]; then
            if ! check_application_health "$app_endpoint"; then
                log "ERROR" "Application health check failed for region $region"
                return 1
            fi
        else
            log "WARN" "No application endpoint found for region $region"
        fi
    fi
    
    log "INFO" "Region $region health check completed successfully"
    return 0
}

# Get database endpoint for region
get_database_endpoint() {
    local region="$1"
    
    # Get database replica endpoint from N8nInstance spec
    kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath="{.spec.multiRegion.regions[?(@.name=='$region')].databaseReplica.endpoint}" 2>/dev/null || echo ""
}

# Get storage bucket for region
get_storage_bucket() {
    local region="$1"
    
    # Get storage bucket from N8nInstance spec
    kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath="{.spec.multiRegion.regions[?(@.name=='$region')].storageReplication.bucket}" 2>/dev/null || echo ""
}

# Get application endpoint for region
get_application_endpoint() {
    local region="$1"
    
    # Construct application endpoint based on region
    local domain=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.spec.domain}' 2>/dev/null || echo "")
    
    if [[ -n "$domain" ]]; then
        echo "https://$domain"
    else
        echo ""
    fi
}

# Check database connectivity
check_database_connectivity() {
    local endpoint="$1"
    local region="$2"
    
    log "INFO" "Testing database connectivity to $endpoint"
    
    # Get database credentials
    local db_secret=$(kubectl get secret -n "$INSTANCE_NAMESPACE" \
        -l "app.kubernetes.io/instance=$INSTANCE_NAME" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$db_secret" ]]; then
        log "ERROR" "Database credentials secret not found"
        return 1
    fi
    
    local db_user=$(kubectl get secret "$db_secret" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.data.username}' | base64 -d 2>/dev/null || echo "")
    local db_password=$(kubectl get secret "$db_secret" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.data.password}' | base64 -d 2>/dev/null || echo "")
    
    if [[ -z "$db_user" ]] || [[ -z "$db_password" ]]; then
        log "ERROR" "Database credentials not found in secret"
        return 1
    fi
    
    # Test connection using pg_isready or similar
    export PGPASSWORD="$db_password"
    if timeout 30 pg_isready -h "$endpoint" -U "$db_user" -d "n8n" &> /dev/null; then
        log "INFO" "Database connectivity test passed"
        return 0
    else
        log "ERROR" "Database connectivity test failed"
        return 1
    fi
}

# Check storage accessibility
check_storage_accessibility() {
    local bucket="$1"
    local region="$2"
    
    log "INFO" "Testing storage accessibility for bucket $bucket in region $region"
    
    # Test S3 bucket access
    if aws s3 ls "s3://$bucket" --region "$region" &> /dev/null; then
        log "INFO" "Storage accessibility test passed"
        return 0
    else
        log "ERROR" "Storage accessibility test failed"
        return 1
    fi
}

# Check application health
check_application_health() {
    local endpoint="$1"
    
    log "INFO" "Testing application health at $endpoint"
    
    # Test application health endpoint
    local health_url="$endpoint/healthz"
    if curl -f -s --max-time 30 "$health_url" &> /dev/null; then
        log "INFO" "Application health test passed"
        return 0
    else
        log "ERROR" "Application health test failed"
        return 1
    fi
}

# Execute database failover
execute_database_failover() {
    log "INFO" "Executing database failover from $SOURCE_REGION to $TARGET_REGION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would promote database replica in $TARGET_REGION"
        return 0
    fi
    
    # Get database replica identifier
    local replica_id=$(get_database_replica_id "$TARGET_REGION")
    if [[ -z "$replica_id" ]]; then
        error_exit "Database replica identifier not found for region $TARGET_REGION"
    fi
    
    log "INFO" "Promoting database replica: $replica_id"
    
    # Promote read replica to primary
    if ! aws rds promote-read-replica \
        --db-instance-identifier "$replica_id" \
        --region "$TARGET_REGION" \
        --backup-retention-period 7 \
        --preferred-backup-window "03:00-04:00"; then
        error_exit "Failed to promote database replica"
    fi
    
    # Wait for promotion to complete
    log "INFO" "Waiting for database promotion to complete..."
    local timeout=$DATABASE_PROMOTION_TIMEOUT
    local elapsed=0
    
    while [[ $elapsed -lt $timeout ]]; do
        local status=$(aws rds describe-db-instances \
            --db-instance-identifier "$replica_id" \
            --region "$TARGET_REGION" \
            --query 'DBInstances[0].DBInstanceStatus' \
            --output text 2>/dev/null || echo "unknown")
        
        if [[ "$status" == "available" ]]; then
            log "INFO" "Database promotion completed successfully"
            break
        elif [[ "$status" == "modifying" ]] || [[ "$status" == "upgrading" ]]; then
            log "INFO" "Database promotion in progress... (status: $status)"
            sleep 30
            elapsed=$((elapsed + 30))
        else
            error_exit "Database promotion failed with status: $status"
        fi
    done
    
    if [[ $elapsed -ge $timeout ]]; then
        error_exit "Database promotion timed out after $timeout seconds"
    fi
    
    log "INFO" "Database failover completed"
}

# Get database replica identifier
get_database_replica_id() {
    local region="$1"
    
    # Construct replica identifier based on naming convention
    echo "${INSTANCE_NAME}-replica-${region}"
}

# Execute storage failover
execute_storage_failover() {
    log "INFO" "Executing storage failover from $SOURCE_REGION to $TARGET_REGION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would update storage configuration for $TARGET_REGION"
        return 0
    fi
    
    # Update N8nInstance to use target region storage
    local target_bucket=$(get_storage_bucket "$TARGET_REGION")
    if [[ -z "$target_bucket" ]]; then
        error_exit "Target storage bucket not found for region $TARGET_REGION"
    fi
    
    log "INFO" "Updating storage configuration to use bucket: $target_bucket"
    
    # Patch N8nInstance resource
    kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        --type='merge' \
        -p="{\"spec\":{\"storage\":{\"s3\":{\"bucket\":\"$target_bucket\",\"region\":\"$TARGET_REGION\"}}}}"
    
    log "INFO" "Storage failover completed"
}

# Execute DNS failover
execute_dns_failover() {
    log "INFO" "Executing DNS failover from $SOURCE_REGION to $TARGET_REGION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would update DNS records to point to $TARGET_REGION"
        return 0
    fi
    
    # Get DNS configuration
    local hosted_zone_id=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.spec.networking.dns.zoneId}' 2>/dev/null || echo "")
    
    if [[ -z "$hosted_zone_id" ]]; then
        log "WARN" "DNS hosted zone ID not configured, skipping DNS failover"
        return 0
    fi
    
    local domain=$(kubectl get n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        -o jsonpath='{.spec.domain}' 2>/dev/null || echo "")
    
    if [[ -z "$domain" ]]; then
        log "WARN" "Domain not configured, skipping DNS failover"
        return 0
    fi
    
    # Get target region load balancer DNS
    local target_lb_dns=$(get_load_balancer_dns "$TARGET_REGION")
    if [[ -z "$target_lb_dns" ]]; then
        error_exit "Target region load balancer DNS not found"
    fi
    
    log "INFO" "Updating DNS record for $domain to point to $target_lb_dns"
    
    # Create Route53 change batch
    local change_batch=$(cat << EOF
{
    "Changes": [
        {
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "$domain",
                "Type": "CNAME",
                "TTL": 60,
                "ResourceRecords": [
                    {
                        "Value": "$target_lb_dns"
                    }
                ]
            }
        }
    ]
}
EOF
)
    
    # Apply DNS changes
    local change_id=$(aws route53 change-resource-record-sets \
        --hosted-zone-id "$hosted_zone_id" \
        --change-batch "$change_batch" \
        --query 'ChangeInfo.Id' \
        --output text)
    
    if [[ -z "$change_id" ]]; then
        error_exit "Failed to update DNS records"
    fi
    
    log "INFO" "DNS change submitted with ID: $change_id"
    
    # Wait for DNS propagation
    log "INFO" "Waiting for DNS propagation..."
    aws route53 wait resource-record-sets-changed --id "$change_id"
    
    log "INFO" "DNS failover completed"
}

# Get load balancer DNS for region
get_load_balancer_dns() {
    local region="$1"
    
    # This would typically be retrieved from the target region's infrastructure
    # For now, construct based on naming convention
    echo "${INSTANCE_NAME}-alb-${region}.elb.amazonaws.com"
}

# Execute application failover
execute_application_failover() {
    log "INFO" "Executing application failover from $SOURCE_REGION to $TARGET_REGION"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN: Would update application configuration for $TARGET_REGION"
        return 0
    fi
    
    # Update N8nInstance to mark target region as active
    kubectl patch n8ninstance "$INSTANCE_NAME" -n "$INSTANCE_NAMESPACE" \
        --type='merge' \
        -p="{\"spec\":{\"multiRegion\":{\"activeRegion\":\"$TARGET_REGION\"}}}"
    
    # Wait for application to be ready in target region
    log "INFO" "Waiting for application to be ready in $TARGET_REGION..."
    
    local timeout=$APPLICATION_STARTUP_TIMEOUT
    local elapsed=0
    
    while [[ $elapsed -lt $timeout ]]; do
        if check_region_health "$TARGET_REGION" "application"; then
            log "INFO" "Application is ready in $TARGET_REGION"
            break
        fi
        
        log "INFO" "Waiting for application to be ready..."
        sleep 30
        elapsed=$((elapsed + 30))
    done
    
    if [[ $elapsed -ge $timeout ]]; then
        error_exit "Application startup timed out after $timeout seconds"
    fi
    
    log "INFO" "Application failover completed"
}

# Send notifications
send_notification() {
    local status="$1"
    local message="$2"
    
    log "INFO" "Sending notification: $status - $message"
    
    # Webhook notification
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        curl -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"instance\": \"$INSTANCE_NAME\",
                \"namespace\": \"$INSTANCE_NAMESPACE\",
                \"sourceRegion\": \"$SOURCE_REGION\",
                \"targetRegion\": \"$TARGET_REGION\",
                \"status\": \"$status\",
                \"message\": \"$message\",
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                \"failoverId\": \"$FAILOVER_ID\"
            }" || log "WARN" "Failed to send webhook notification"
    fi
    
    # SNS notification
    if [[ -n "${SNS_TOPIC_ARN:-}" ]]; then
        aws sns publish \
            --topic-arn "$SNS_TOPIC_ARN" \
            --message "$message" \
            --subject "N8n Failover: $status" || log "WARN" "Failed to send SNS notification"
    fi
    
    # Slack notification
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{
                \"text\": \"N8n Failover $status\",
                \"attachments\": [
                    {
                        \"color\": \"$([ "$status" == "success" ] && echo "good" || echo "danger")\",
                        \"fields\": [
                            {\"title\": \"Instance\", \"value\": \"$INSTANCE_NAME\", \"short\": true},
                            {\"title\": \"Source Region\", \"value\": \"$SOURCE_REGION\", \"short\": true},
                            {\"title\": \"Target Region\", \"value\": \"$TARGET_REGION\", \"short\": true},
                            {\"title\": \"Status\", \"value\": \"$status\", \"short\": true},
                            {\"title\": \"Message\", \"value\": \"$message\", \"short\": false}
                        ]
                    }
                ]
            }" || log "WARN" "Failed to send Slack notification"
    fi
}

# Generate failover ID
generate_failover_id() {
    local timestamp=$(date +%Y%m%d-%H%M%S)
    echo "failover-${INSTANCE_NAME}-${SOURCE_REGION}-${TARGET_REGION}-${timestamp}"
}

# Save failover state
save_failover_state() {
    local failover_id="$1"
    local state_file="/tmp/n8n-failover-${failover_id}.json"
    
    cat > "$state_file" << EOF
{
    "failoverId": "$failover_id",
    "instanceName": "$INSTANCE_NAME",
    "instanceNamespace": "$INSTANCE_NAMESPACE",
    "sourceRegion": "$SOURCE_REGION",
    "targetRegion": "$TARGET_REGION",
    "startTime": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "status": "in-progress"
}
EOF
    
    log "INFO" "Failover state saved to $state_file"
}

# Load failover state
load_failover_state() {
    local failover_id="$1"
    local state_file="/tmp/n8n-failover-${failover_id}.json"
    
    if [[ -f "$state_file" ]]; then
        log "INFO" "Loading failover state from $state_file"
        
        INSTANCE_NAME=$(jq -r '.instanceName' "$state_file")
        INSTANCE_NAMESPACE=$(jq -r '.instanceNamespace' "$state_file")
        SOURCE_REGION=$(jq -r '.sourceRegion' "$state_file")
        TARGET_REGION=$(jq -r '.targetRegion' "$state_file")
        
        log "INFO" "Failover state loaded successfully"
    else
        error_exit "Failover state file not found: $state_file"
    fi
}

# Execute rollback
execute_rollback() {
    log "INFO" "Executing rollback for failover ID: $FAILOVER_ID"
    
    # Load failover state
    load_failover_state "$FAILOVER_ID"
    
    # Swap source and target regions for rollback
    local temp_region="$SOURCE_REGION"
    SOURCE_REGION="$TARGET_REGION"
    TARGET_REGION="$temp_region"
    
    log "INFO" "Rolling back from $SOURCE_REGION to $TARGET_REGION"
    
    # Execute rollback steps (same as failover but in reverse)
    execute_application_failover
    execute_dns_failover
    execute_storage_failover
    # Note: Database rollback is more complex and may require manual intervention
    
    log "INFO" "Rollback completed successfully"
    send_notification "rollback-success" "Rollback completed successfully"
}

# Main failover function
main() {
    log "INFO" "Starting n8n disaster recovery failover"
    log "INFO" "Instance: $INSTANCE_NAME (namespace: $INSTANCE_NAMESPACE)"
    
    if [[ "$ROLLBACK" == "true" ]]; then
        log "INFO" "Mode: Rollback (ID: $FAILOVER_ID)"
    else
        log "INFO" "Mode: Failover ($SOURCE_REGION -> $TARGET_REGION)"
        log "INFO" "Dry run: $DRY_RUN"
        log "INFO" "Force failover: $FORCE_FAILOVER"
    fi
    
    # Load configuration and validate environment
    load_config
    validate_environment
    
    if [[ "$ROLLBACK" == "true" ]]; then
        execute_rollback
        return 0
    fi
    
    # Check prerequisites
    check_prerequisites
    
    # Generate failover ID
    FAILOVER_ID=$(generate_failover_id)
    log "INFO" "Failover ID: $FAILOVER_ID"
    
    # Save failover state
    save_failover_state "$FAILOVER_ID"
    
    # Check source region health (unless forced)
    if [[ "$FORCE_FAILOVER" != "true" ]]; then
        if check_region_health "$SOURCE_REGION"; then
            log "WARN" "Source region appears healthy. Use --force to proceed anyway."
            if [[ "$DRY_RUN" != "true" ]]; then
                error_exit "Aborting failover due to healthy source region"
            fi
        fi
    fi
    
    # Check target region health
    if ! check_region_health "$TARGET_REGION"; then
        error_exit "Target region is not healthy, cannot proceed with failover"
    fi
    
    # Execute failover steps
    log "INFO" "Beginning failover execution..."
    
    execute_database_failover
    execute_storage_failover
    execute_dns_failover
    execute_application_failover
    
    # Final health check
    log "INFO" "Performing final health check..."
    if ! check_region_health "$TARGET_REGION"; then
        error_exit "Post-failover health check failed"
    fi
    
    # Send success notification
    send_notification "success" "Failover from $SOURCE_REGION to $TARGET_REGION completed successfully"
    
    log "INFO" "Failover completed successfully"
    log "INFO" "Failover ID: $FAILOVER_ID"
    log "INFO" "To rollback, run: $0 --rollback --failover-id $FAILOVER_ID"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source-region)
            SOURCE_REGION="$2"
            shift 2
            ;;
        --target-region)
            TARGET_REGION="$2"
            shift 2
            ;;
        --instance-name)
            INSTANCE_NAME="$2"
            shift 2
            ;;
        --instance-namespace)
            INSTANCE_NAMESPACE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN="true"
            shift
            ;;
        --force)
            FORCE_FAILOVER="true"
            shift
            ;;
        --rollback)
            ROLLBACK="true"
            shift
            ;;
        --failover-id)
            FAILOVER_ID="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help)
            cat << EOF
Usage: $0 [OPTIONS]

Options:
    --source-region REGION      Source region for failover
    --target-region REGION      Target region for failover
    --instance-name NAME        N8nInstance name
    --instance-namespace NS     N8nInstance namespace (default: n8n-production)
    --dry-run                   Perform dry run without making changes
    --force                     Force failover even if source region is healthy
    --rollback                  Rollback a previous failover
    --failover-id ID            Failover ID for rollback
    --config FILE               Configuration file path
    --help                      Show this help message

Examples:
    # Perform failover
    $0 --source-region us-west-2 --target-region us-east-1 --instance-name my-n8n

    # Dry run
    $0 --source-region us-west-2 --target-region us-east-1 --instance-name my-n8n --dry-run

    # Force failover
    $0 --source-region us-west-2 --target-region us-east-1 --instance-name my-n8n --force

    # Rollback
    $0 --rollback --failover-id failover-my-n8n-us-west-2-us-east-1-20231215-143022
EOF
            exit 0
            ;;
        *)
            error_exit "Unknown option: $1"
            ;;
    esac
done

# Run main function
main "$@"
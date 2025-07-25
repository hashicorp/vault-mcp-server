#!/bin/bash

# Example script demonstrating the configure_ui_headers tool usage
# This script shows common patterns for configuring UI headers in different environments

echo "=== Vault UI Headers Configuration Examples ==="
echo

# Example 1: Production Environment Setup
echo "1. Setting up Production environment headers..."
echo "   Headers: Environment=Production, Cluster=prod-us-east-1, Warning=PRODUCTION ENVIRONMENT"
echo "   Command: mcp call configure_ui_headers with JSON format"
echo '   {"headers": "{\"X-Environment\":\"Production\",\"X-Cluster\":\"prod-us-east-1\",\"X-Warning\":\"⚠️ PRODUCTION ENVIRONMENT ⚠️\"}", "operation": "update"}'
echo

# Example 2: Staging Environment Setup  
echo "2. Setting up Staging environment headers..."
echo "   Headers: Environment=Staging, Cluster=staging-us-west-2"
echo "   Command: mcp call configure_ui_headers with key=value format"
echo '   {"headers": "X-Environment=Staging,X-Cluster=staging-us-west-2,X-Notice=Testing Environment", "operation": "replace"}'
echo

# Example 3: Development Environment Setup
echo "3. Setting up Development environment headers..."
echo "   Headers: Environment=Development, Version=latest, Owner=DevTeam"
echo "   Command: mcp call configure_ui_headers"
echo '   {"headers": "X-Environment=Development,X-Version=latest,X-Owner=DevTeam,X-Notice=🔧 Dev Environment", "operation": "update"}'
echo

# Example 4: Adding temporary maintenance notice
echo "4. Adding temporary maintenance notice..."
echo "   Command: mcp call configure_ui_headers"
echo '   {"headers": "X-Maintenance=Scheduled maintenance window: Sunday 2AM-4AM UTC", "operation": "update"}'
echo

# Example 5: Removing temporary headers
echo "5. Removing temporary headers after maintenance..."
echo "   Command: mcp call configure_ui_headers to delete specific headers"
echo '   {"headers": "X-Maintenance", "operation": "delete"}'
echo

# Example 6: Compliance setup for financial environment
echo "6. Financial services compliance setup..."
echo "   Headers: Environment, Compliance notice, Audit info"
echo "   Command: mcp call configure_ui_headers"
echo '   {"headers": "{\"X-Environment\":\"PROD-FINANCIAL\",\"X-Compliance\":\"SOX Compliant Environment\",\"X-Audit\":\"All access logged\"}", "operation": "replace"}'
echo

# Example 7: Multi-region setup
echo "7. Multi-region environment identification..."
echo "   Headers: Environment, Region, Cluster"
echo "   Command: mcp call configure_ui_headers"
echo '   {"headers": "X-Environment=Production,X-Region=EU-WEST-1,X-Cluster=prod-eu-west-1-cluster-01,X-Timezone=CET", "operation": "update"}'
echo

echo "=== Best Practices ==="
echo "• Use consistent naming conventions (e.g., X-Environment, X-Cluster)"
echo "• Include visual indicators (emojis) for critical environments"
echo "• Keep header values concise and informative"
echo "• Use 'update' operation to add headers, 'replace' to completely change them"
echo "• Use 'delete' operation to remove temporary notices"
echo "• Test header configurations in development before applying to production"
echo

echo "=== Security Notes ==="
echo "• Headers are visible to all Vault UI users"
echo "• Do not include sensitive information in header values"
echo "• Consider impact on performance with many headers"
echo "• Headers are stored in Vault configuration (backed up with config)"
echo

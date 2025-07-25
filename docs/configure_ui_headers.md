# Configure UI Headers Tool

The `configure_ui_headers` tool allows you to configure custom UI headers in HashiCorp Vault for environment identification. These headers help users and administrators identify which Vault environment (development, staging, production, etc.) they are accessing through the Vault UI.

## Purpose

Custom UI headers are particularly useful for:

- **Environment Identification**: Display environment names (e.g., "Production", "Staging", "Development") in the Vault UI
- **Cluster Information**: Show cluster names or regions (e.g., "us-east-1", "eu-west-1")
- **Warning Messages**: Display important notices or warnings for specific environments
- **Compliance**: Meet organizational requirements for environment labeling

## Usage

### Tool Parameters

- **headers** (required): Headers to configure, can be provided in two formats:
  - JSON format: `{"X-Environment":"Production","X-Cluster":"us-east-1"}`
  - Key=value format: `X-Environment=Production,X-Cluster=us-east-1`

- **operation** (optional, default: "update"): Operation to perform:
  - `update`: Merge with existing headers (adds or updates specified headers)
  - `replace`: Replace all existing headers with new ones
  - `delete`: Remove specified headers from configuration

### Examples

#### Setting Environment Headers (JSON format)
```json
{
  "headers": "{\"X-Environment\":\"Production\",\"X-Cluster\":\"us-east-1\",\"X-Warning\":\"PRODUCTION ENVIRONMENT\"}",
  "operation": "update"
}
```

#### Setting Environment Headers (Key=Value format)
```json
{
  "headers": "X-Environment=Production,X-Cluster=us-east-1,X-Warning=PRODUCTION ENVIRONMENT",
  "operation": "update"
}
```

#### Replacing All Headers
```json
{
  "headers": "X-Environment=Staging,X-Region=us-west-2",
  "operation": "replace"
}
```

#### Deleting Specific Headers
```json
{
  "headers": "X-Warning,X-Temp-Notice",
  "operation": "delete"
}
```

### Common Header Names

While you can use any header name, these are commonly used patterns:

- `X-Environment`: Environment name (Production, Staging, Development)
- `X-Cluster`: Cluster or datacenter identifier
- `X-Region`: Geographic region
- `X-Warning`: Warning or notice messages
- `X-Version`: Application or environment version
- `X-Owner`: Team or department responsible

## How UI Headers Work in Vault

When configured, these headers will be sent with HTTP responses from Vault's UI endpoints. The Vault web interface can display these headers to users, typically in:

- Header bars or banners
- Environment indicators
- Warning messages
- Status displays

## Security Considerations

- Headers are visible to anyone accessing the Vault UI
- Don't include sensitive information in header values
- Consider the impact on performance with large numbers of headers
- Headers are stored in Vault's configuration and will be backed up with other config data

## Vault API Endpoint

This tool configures the `sys/config/ui/headers` endpoint in Vault. For more information, refer to the [Vault API documentation](https://developer.hashicorp.com/vault/api-docs/system/config-ui).

## Prerequisites

- Vault server must support the UI headers configuration endpoint
- Appropriate permissions to modify Vault system configuration
- Vault client must be properly authenticated and configured

## Error Handling

The tool provides detailed error messages for common issues:

- Invalid header format
- Vault client connection problems
- Insufficient permissions
- Vault API errors

## Related Tools

- `get_ui_headers`: Retrieve current UI headers configuration
- `update_cors_config`: Configure CORS settings for Vault UI

# Authru

A simple, serverless and stateless authentication gateway for client applications that need to interact with third-party APIs while keeping authentication tokens server-side.

## Features

- 🔐 **Secure Token Management**: Uses AWS Parameter Store for encrypted token storage
- 🌐 **Domain Restriction**: CORS and origin validation for security
- 📊 **Cost-Optimized Monitoring**: CloudWatch with configurable retention policies
- 🔧 **Extensible Configuration**: JSON-based routing and policy system

## Quick Start

### Prerequisites

- AWS CLI configured
- Python 3.12+
- Terraform 1.0+
- GNU Make 4.3+ (optional)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd authru

# Install dependencies
make install

# Run tests
make test

# Bootstrap Terraform
make bootstrap

# Deploy to AWS
make deploy
```


## Request Flow

1. **Client Request**: Client sends request to API Gateway endpoint
2. **CORS Validation**: Origin is validated against allowed domains
3. **Route Matching**: Request path is matched against configured routes
4. **Authentication**: If no auth header exists, credentials are retrieved from Parameter Store
5. **Request Forwarding**: Request is forwarded to target API with authentication
6. **Response Passthrough**: Response is returned to client with original status/headers

## Configuration

### Route Configuration

Routes are defined in `config/routes.json`:

```json
{
  "routes": [
    {
      "name": "my-api",
      "pathPattern": "/api/v1/*",
      "targetBaseUrl": "https://api.example.com",
      "authentication": {
        "scheme": "Bearer",
        "parameterName": "/authru/tokens/my-api"
      },
      "policies": {
        "timeout": 30000,
        "retries": 3
      }
    }
  ]
}
```

#### Route Fields

- **name**: Unique identifier for the route
- **pathPattern**: URL pattern to match (supports `*` wildcard)
- **targetBaseUrl**: Base URL of the target API
- **authentication.scheme**: Authentication scheme (`Bearer`, `Basic` and `ApiKey` supported)
- **authentication.parameterName**: AWS Parameter Store parameter name
- **policies.timeout**: Request timeout in milliseconds (optional)
- **policies.retries**: Number of retry attempts (optional)

### Security Configuration

```json
{
  "security": {
    "allowedOrigins": [
      "https://yourdomain.com",
      "https://app.yourdomain.com",
      "*.yourdomain.com"
    ],
    "corsEnabled": true,
    "allowCredentials": false
  }
}
```

#### Security Fields

- **allowedOrigins**: List of allowed origins for CORS
- **corsEnabled**: Enable/disable CORS validation
- **allowCredentials**: Allow credentials in CORS requests

### Monitoring Configuration

```json
{
  "monitoring": {
    "logRetentionDays": 7,
    "logLevel": "INFO",
    "enableMetrics": true,
    "enableTracing": false
  }
}
```

## API Endpoints

### Proxy Endpoint

**All HTTP Methods**: `/{proxy+}`

Forwards requests to configured third-party APIs based on path matching.

#### Request Headers

- **Origin**: Required for CORS validation
- **Authorization**: Optional - if present, will be passed through; if missing, will be added

#### Response

Returns the exact response from the target API, including:
- Status code
- Headers (with CORS headers added)
- Body content

#### Example

```bash
# Client request
curl -X GET "https://your-api-gateway-url/api/v1/users?limit=10" \
  -H "Origin: https://yourdomain.com" \
  -H "Accept: application/json"

# Forwarded to target API as:
curl -X GET "https://api.example.com/v1/users?limit=10" \
  -H "Authorization: Bearer <base64-encoded-credentials>" \
  -H "Accept: application/json"
```

### CORS Preflight

**OPTIONS**: `/{proxy+}`

Handles CORS preflight requests.

#### Response Headers

- `Access-Control-Allow-Origin`: Matched origin or `*`
- `Access-Control-Allow-Methods`: Allowed HTTP methods
- `Access-Control-Allow-Headers`: Allowed request headers
- `Access-Control-Max-Age`: Cache duration for preflight

## Authentication

All credentials are stored in AWS Parameter Store and processed according to the following flow:

1. Retrieve credentials from Parameter Store
2. Base64 encode `credentials`
3. Add as `Authorization: <Scheme> <encoded-credentials>` header

### Parameter Store Setup

```bash
# Store credentials securely
aws ssm put-parameter \
  --name "/authru/tokens/my-api" \
  --value "your-username:your-password" \
  --type "SecureString" \
  --region eu-west-1
```

## Error Responses

All errors return JSON with consistent format:

```json
{
  "error": "Error message",
  "statusCode": 400
}
```

### Common Error Codes

- **403**: Origin not allowed (CORS violation)
- **404**: No matching route found
- **500**: Configuration or authentication error
- **502**: Target API error or timeout

## Path Matching

Routes use glob-style patterns:

- `/api/v1/*` matches `/api/v1/users`, `/api/v1/orders/123`
- `/webhooks/*` matches `/webhooks/stripe`, `/webhooks/github`
- Exact matches: `/health` only matches `/health`

The matched prefix is removed when forwarding:
- Route pattern: `/api/v1/*`
- Request path: `/api/v1/users/123`
- Forwarded path: `/users/123`

## CORS Support

### Allowed Origins

Configure allowed origins in the security section:

```json
{
  "allowedOrigins": [
    "https://yourdomain.com",      // Exact match
    "*.yourdomain.com",            // Subdomain wildcard
    "*"                            // Allow all (not recommended)
  ]
}
```

### Preflight Handling

The proxy automatically handles OPTIONS requests for CORS preflight:

1. Validates origin against allowed list
2. Returns appropriate CORS headers
3. Caches preflight response for 24 hours

## Monitoring and Logging

### CloudWatch Logs

Structured JSON logs include:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "INFO",
  "logger": "src.handlers.proxy_handler",
  "message": "Forwarding GET request to https://api.example.com/users",
  "route_name": "my-api",
  "method": "GET",
  "target_url": "https://api.example.com/users"
}
```

### Metrics

Available CloudWatch metrics:
- Lambda invocations, errors, duration
- API Gateway requests, latency, errors
- Custom metrics for route-specific monitoring

### Cost Optimization

- Log retention: 7 days (configurable)
- Log level: INFO (configurable)
- Structured logging for efficient querying
- Parameter Store caching for reduced API calls

## Security Considerations

### Best Practices

1. **Least Privilege**: Grant minimal IAM permissions
2. **Secure Parameters**: Use SecureString type in Parameter Store
3. **Origin Validation**: Always configure allowed origins
4. **Regular Rotation**: Rotate API credentials regularly
5. **Monitoring**: Monitor for unusual access patterns

### IAM Permissions

Lambda function needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/authru/*"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **403 Origin not allowed**
   - Check `allowedOrigins` configuration
   - Verify Origin header in request

2. **404 No matching route**
   - Check route `pathPattern` configuration
   - Verify request path format

3. **500 Authentication error**
   - Verify Parameter Store parameter exists
   - Check IAM permissions for Lambda
   - Validate credential format (`username:password`)

4. **502 Bad Gateway**
   - Check target API availability
   - Verify `targetBaseUrl` configuration
   - Check timeout settings

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
LOG_LEVEL=DEBUG

# Or update Lambda configuration
aws lambda update-function-configuration \
  --function-name authru \
  --environment Variables='{LOG_LEVEL=DEBUG}'
```


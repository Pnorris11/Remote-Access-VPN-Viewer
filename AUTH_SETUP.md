# RAVPN Authentication Setup Guide

This guide explains how to configure OIDC or SAML authentication for the RAVPN monitoring application.

## Overview

The RAVPN application now supports both OpenID Connect (OIDC) and SAML authentication to ensure only authorized users can access VPN monitoring data. The application includes:

- **OIDC Support**: Modern OAuth 2.0 / OpenID Connect authentication
- **SAML Support**: Enterprise SAML 2.0 authentication
- **Authorization Controls**: Domain and group-based access control
- **Session Management**: Secure session handling with configurable timeouts

## Quick Start (OIDC)t

1. **Configure your identity provider** (e.g., Azure AD, Okta, Google, etc.)
2. **Copy environment file**: `cp .env.example .env`
3. **Update .env file** with your OIDC settings
4. **Install dependencies**: `pip install -r requirements.txt`
5. **Run the application**: `python app.py`

## Environment Configuration

### Required Security Settings

```bash
# Flask Security Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production  # MUST be changed!
SESSION_COOKIE_SECURE=True  # Set to False for local development
SESSION_COOKIE_HTTPONLY=True
```

### OIDC Configuration

Enable OIDC and configure your identity provider:

```bash
# OIDC Authentication Configuration
OIDC_ENABLED=True
OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
OIDC_DISCOVERY_URL=https://your-oidc-provider.com/.well-known/openid_configuration
OIDC_REDIRECT_URI=https://your-app-domain.com/auth/callback
```

### SAML Configuration

Alternative to OIDC - enable SAML:

```bash
# SAML Authentication Configuration
SAML_ENABLED=True
SAML_SP_ENTITY_ID=your-sp-entity-id
SAML_SP_ASSERTION_CONSUMER_SERVICE_URL=https://your-app-domain.com/saml/acs
SAML_IDP_ENTITY_ID=your-idp-entity-id
SAML_IDP_SSO_URL=https://your-idp.com/sso
SAML_IDP_X509_CERT=your-idp-certificate
```

### Authorization Controls

Optional - restrict access by email domain or group membership:

```bash
# Authorization (optional)
AUTHORIZED_DOMAINS=yourcompany.com,yourpartner.com
AUTHORIZED_GROUPS=vpn-admins,network-team
```

## Identity Provider Setup

### Azure AD (OIDC)

1. **Register Application**:
   - Go to Azure AD > App registrations > New registration
   - Name: "RAVPN Monitor"
   - Redirect URI: `https://your-domain.com/auth/callback`

2. **Configure Application**:
   - Note the Application (client) ID
   - Create a client secret
   - Add API permissions: `openid`, `profile`, `email`

3. **Environment Variables**:
   ```bash
   OIDC_CLIENT_ID=your-azure-app-id
   OIDC_CLIENT_SECRET=your-azure-client-secret
   OIDC_DISCOVERY_URL=https://login.microsoftonline.com/your-tenant-id/v2.0/.well-known/openid_configuration
   ```

### Okta (OIDC)

1. **Create Application**:
   - Okta Admin > Applications > Create App Integration
   - Sign-on method: OIDC, Application type: Web Application
   - Sign-in redirect URIs: `https://your-domain.com/auth/callback`

2. **Environment Variables**:
   ```bash
   OIDC_CLIENT_ID=your-okta-client-id
   OIDC_CLIENT_SECRET=your-okta-client-secret
   OIDC_DISCOVERY_URL=https://your-okta-domain.okta.com/.well-known/openid_configuration
   ```

### Google (OIDC)

1. **Create OAuth 2.0 Credentials**:
   - Google Cloud Console > APIs & Services > Credentials
   - Create OAuth 2.0 Client ID
   - Authorized redirect URIs: `https://your-domain.com/auth/callback`

2. **Environment Variables**:
   ```bash
   OIDC_CLIENT_ID=your-google-client-id.googleusercontent.com
   OIDC_CLIENT_SECRET=your-google-client-secret
   OIDC_DISCOVERY_URL=https://accounts.google.com/.well-known/openid_configuration
   ```

## Deployment

### Docker Deployment

```bash
# Build the image
docker build -t ravpn-monitor .

# Run with environment file
docker run -d --name ravpn \
  --env-file .env \
  -p 5000:5000 \
  ravpn-monitor
```

### Production Considerations

1. **HTTPS Required**: Always use HTTPS in production
2. **Secure SECRET_KEY**: Generate a cryptographically secure secret key
3. **Session Security**: Enable secure cookies (`SESSION_COOKIE_SECURE=True`)
4. **Reverse Proxy**: Use nginx or similar for SSL termination
5. **Log Monitoring**: Monitor authentication logs for security events

## Security Features

### Access Control

- **Domain Restriction**: Limit access to specific email domains
- **Group-based Access**: Require membership in specific groups
- **Session Timeout**: Configurable session lifetime (default: 8 hours)
- **Secure Cookies**: HTTPOnly and Secure cookie flags

### Authentication Flow

1. User accesses protected route
2. Redirected to configured identity provider
3. User authenticates with IdP
4. IdP redirects back with authentication token
5. Application validates token and creates session
6. Authorization check (domain/group membership)
7. Access granted or denied

## API Access

The `/api/sessions` endpoint requires authentication. For programmatic access:

1. **Service Account**: Create a service account in your IdP
2. **Client Credentials**: Use OAuth 2.0 client credentials flow
3. **API Key**: Implement API key authentication (custom development)

## Troubleshooting

### Common Issues

1. **"Authentication not configured"**:
   - Ensure either `OIDC_ENABLED=True` or `SAML_ENABLED=True`
   - Verify all required environment variables are set

2. **"Access denied"**:
   - Check `AUTHORIZED_DOMAINS` and `AUTHORIZED_GROUPS` settings
   - Verify user's email domain and group membership

3. **OIDC callback errors**:
   - Verify `OIDC_REDIRECT_URI` matches IdP configuration
   - Check client ID and secret are correct
   - Ensure discovery URL is accessible

4. **Session issues**:
   - Verify `SECRET_KEY` is set and consistent across restarts
   - Check session cookie settings for HTTPS requirements

### Debug Mode

For development, set these environment variables:

```bash
SESSION_COOKIE_SECURE=False  # Allow HTTP cookies
FLASK_DEBUG=True            # Enable debug mode
```

### Logs

Authentication events are logged at INFO level:
- User login/logout events
- Authentication failures
- Authorization decisions

Monitor logs for security events:

```bash
docker logs ravpn
# or
tail -f /var/log/ravpn/app.log
```

## Support

For additional configuration or troubleshooting:

1. Check application logs for error messages
2. Verify IdP configuration and connectivity
3. Test authentication flow manually
4. Review network and firewall settings

## Security Disclosure

If you discover a security vulnerability, please follow responsible disclosure practices and contact the development team directly.
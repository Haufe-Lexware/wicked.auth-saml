# Authorization Server for SAML Web SSO

This repository contains the source code for a wicked.haufe.io Authorization Server needed to implement the OAuth 2.0 Implicit Flow in conjunction with SAML Web SSO (identity federation).

For testing purposes, there is a pre-built docker image (`haufelexware/wicked.auth-saml:dev`) with this repository you may use. It's not advisable to use this image in production; please fork it, copy it, or similar, and build your own image which you know to work with your specific Web SSO environment.

## Add `auth-saml` to your environment (using `docker-compose`)

Incorporate a container with the image `haufelexware/wicked.auth-saml` in your container setup. If you are using `docker-compose`, you will need an additional service:

```yml
version: '2'

services:
  # ...

  auth-saml:
    env_file: variables.env
    image: haufelexware/wicked.auth-saml:dev
    depends_on:
    - portal-api
    - portal-kong-adapter
    command: "npm start"
    restart: unless-stopped
```

In case you are using different deployment methods of your API Portal, this may differ for your setup (e.g. `docker swarm`).

This docker container is intended to be part of a wicked deployment, inside the same docker network as all other wicked components. It needs to talk to both the wicked portal API and the Kong Adapter (to create access tokens).

### Adding to wicked configuration

Use the portal kickstarter to register a new "Authorization Server":

* Server ID: `auth-saml`
* Upstream URL: `http://auth-saml:3011/`
* Request Path: `/auth-saml`
* Strip request path: No
* Preserve Host: No

Add plugins to the server definition if you feel like it; `Correlation Id` is definitely a good idea.

### Add SAML information

Open up the `auth-saml.json` file in the `static/auth-servers` directory in an editor and add the following sections to the definition:

```json
{
  "id": "auth-saml",
  "name": "auth-saml",
  "desc": "Authorization Server SAML Web SSO",
  "url": "https://${PORTAL_NETWORK_APIHOST}/auth-saml/api/{{apiId}}?client_id=<your app's client id>&response_type=token&redirect_uri=<your app's redirect uri>[&state=<client state>]",
  "urlDescription": "In case you need an access token, call the above link with your `client_id` (for the subscribed API) substituted in the link. In case the authentication is successful, you will get called back at your registered `redirect_uri` with the access token attached in the fragment of the URI. Any `state` you pass in will get passed back with the access token, as an additional query parameter `&state=<...>`.",
  "config": {
    "api": {
      "upstream_url": "http://auth-saml:3011",
      "request_path": "/auth-saml"
    },
    "plugins": [
      {
        "config": {
          "header_name": "Correlation-Id",
          "generator": "uuid"
        },
        "name": "correlation-id"
      }
    ]
  },
  "saml": {
    "profile": {
      "authenticated_userid": "saml:{{{userid}}}",
      "first_name": "{{{first_name}}}",
      "last_name": "{{{family_name}}}",
      "name": "{{{name}}}",
      "email": "{{{email}}}",
      "company": "{{{company}}}"
    },
    "spOptions": {
      "entity_id": "https://${PORTAL_NETWORK_APIHOST}/auth-saml/metadata.xml",
      "assert_endpoint": "https://${PORTAL_NETWORK_APIHOST}/auth-saml/assert",
      "nameid_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
      "certificate": "${SAML_SP_CERTIFICATE}",
      "private_key": "${SAML_SP_PRIVATE_KEY}"
    },
    "idpOptions": {
      "sso_login_url": "${SAML_IDP_LOGIN_URL}",
      "certificates": [
        "${SAML_IDP_CERTIFICATE}"
      ]
    }
  }
}
```

Then go into the kickstarter's environment definition and fill in the "blanks", e.g. `SAML_ENTITY_ID` and the certificates you need (as oneliners, lines separated by `\n`).

### The `profile` section

In the SAML configuration section, you can specify how the result of the `/auth-saml/profile` CORS-enabled end point should look like. It uses [mustache](https://mustache.github.io/mustache.5.html) syntax, taking the SAML profile attributes as property name parameters. It's also possible to use multiple attribute names in a specific string, just use the mustache syntax, e.g. 

```json
"saml": {
  "profile": {
    "authenticated_userid": "userid={{{userid}}};usergroup={{{group}}}",
    "full_name": "{{{first_name}}} {{{last_name}}}"
  }
  // ...
}
```

**IMPORTANT 1**: The only mandatory property here is **`authenticated_userid`** which is the string which is passed in via `X-Authenticated-Userid` to backend APIs secured via the SSO login.

**IMPORTANT 2**: All property names are **lower case**.

## Creating certificates

This Authorization Server implements a SAML SP (Service Provider), and thus also needs its own Certificate/Key pair. It's perfectly fine to use self-signed certificates for that, using e.g. a tool like `openssl`:

```bash
$ openssl req -x509 -newkey rsa:2048 -keyout saml-key.pem -out saml-cert.pem -nodes -subj "/CN=yourcompany.com" -days 730
```

Paste the content of `saml-cert.pem` into the `SAML_SP_CERTIFICATE` environment variable, and `saml-key.pem` into `SAML_SP_PRIVATE_KEY`. Please make sure that the kickstarter encrypts at least the private key in your configuration.

## Additional end points

### Retrieving the profile

As an SPA, you may do a CORS call to the `/auth-saml/profile` end point to retrieve the profile the SAML IdP passed on to the Authorization Server. It will be formatted as specified in the `profile` property of the configuration.

Please note the following:

* This call will only succeed via the same user agent as did the SAML login on the Authorization Server (via CORS)
* The CORS call **must** pass its credentials (`withCredentials: true` with `XMLHttpRequest` or `credentials: 'include'` with `fetch`)
* Only CORS calls from the same `Origin` as the SPA itself (i.e. the redirect URI which was specified for it in the API Portal) will succeed, all others will be rejected

### Renewing the Access Token

The end point `/auth-saml/heartbeat` can be used to - via CORS/AJAX - renew the access token, as long as the User Agent the SPA lives in still has a valid session with Authorization Server.

The same restrictions as for the `/auth-saml/profile` end point apply: Credentials must be passed, and the same `Origin`, and same User Agent.

If successful, the end point will reply with the following content:

```json
{
  "access_token": "sifzeriuotzhi4e5o84e653487594385",
  "expires_in": 3600,
  "token_type:" "bearer"
}
```

## Adding Authorization

As `wicked.auth-passport`, `wicked.auth-saml` does not do any kind of Authorization, just federates Authentication to an SSO SAML Identity Provider. In case that was successful, that is considered "enough" to also authorize the user for use with the API.

In the code you can see a large comment in the `app.post('/auth-saml/assert')` end point where additional steps could be done to actually authorize the user, e.g. retrieve licenses from a license API/database, or whatever you need.

In the future, I might add a plugin entry point here, so that you could really use the plain `wicked.auth-saml` component with your production scenario, and just delegate the creation of the scopes (or rejecting the user) to an actual authorization server. 

## Tweaking behaviour

### Change base request path: `AUTH_SERVER_BASE`

As a default, the `wicked.auth-saml` server serves from the base path `/auth-saml`. You may change this by supplying the `AUTH_SERVER_BASE` environment variable at startup. The base path needs to start with a `/` (slash) and end without a slash. Supplying an empty string is also allowed, in this case all end points are served from the root, e.g. `/profile`.

```bash
$ export AUTH_SERVER_BASE=/auth
```

### Changing session timeout: `AUTH_SERVER_SESSION_MINUTES`

The default session length for the authorization server is 60 minutes. Change this value by supplying an environment variable `AUTH_SERVER_SESSION_MINUTES` before/at startup.

```bash
$ export AUTH_SERVER_SESSION_MINUTES=15
```

### Change authorization server ID: `AUTH_SERVER_NAME``

The default authorization server name is `auth-saml`. This is the id which is used to retrieve the configuration data from the wicked API. You may change this name (e.g. in order to support multiple SAML SSO services) by defining the environment variable `AUTH_SERVER_NAME`.

```bash
$ export AUTH_SERVER_NAME=my-auth-server
```
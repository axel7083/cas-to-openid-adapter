# cas-to-openid-adapter

This project has been made to create an adapter between a cas Authentication service and a OpenID client.

The code is mainly from [zitadel/oidc](https://github.com/zitadel/oidc/tree/v2.2.3/example/server) as they provide a service example implementation for OpenID protocol.

## Setup

### Generate RSA keys

You need a public and private keys
```sh
openssl genrsa -out rsa.private 2048
openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM
```

Copy those files inside a key folder.

### Build the docker image
```sh
docker build -f Dockerfile .
```

### Start the docker image
You can configure the adapter with environement variable:
| env                   | default                              | description                                     |
|-----------------------|--------------------------------------|-------------------------------------------------|
| HOST                  | localhost                            | The host address to listen to                   |
| PORT                  | 9998                                 | The host port to listen to                      |
| ISSUER                | http://localhost:9998/               | The issuer for the JWT token                    |
| CAS_ADDRESS           | ❌                                    | The CAS address to use                          |
| CAS_LOGIN_ENDPOINT    | /login                               | The CAS endpoint to use for login               |
| CAS_VALIDATE_ENDPOINT | /serviceValidate                     | The CAS endpoint to use for validate the ticket |
| CLIENT_ID             | web                                  | The Client id to use for the OpenID protocol.   |
| CLIENT_SECRET         | ❌                                    | Client secret to use by the OpenID client       |
| CLIENT_REDIRECT_URI   | http://localhost:9999/auth/callback  | redirect URI allowed for the OpenID client      |
| OPENID_KEY_PHRASE     | ❌                                    | will be sha256-sum and used for encryption      |
| SIGNING_PRIVATE_KEY   | ❌                                    | The path to the private signing key.            |
| SIGNING_PUBLIC_KEY    | ❌                                    | The path to the public singing key.             |
| SIGNING_KEY_ID        | 682a39b4-cf9f-40de-9fdd-b5c78ff07fe4 | The key ID                                      |

## Status

This project has only been used a demonstration, and is **not maintained**.
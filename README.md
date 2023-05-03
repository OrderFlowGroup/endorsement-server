# DFlow Endorsement Server
This guide is for order flow sources who intend to route orders via DFlow order flow auctions (OFAs). In order to do so, an order flow source must run an _endorsement server_. This repository contains an implementation of an endorsement server by DFlow.

An endorsement server endorses an order flow source's users' quote requests. By endorsing its users' quote requests, an order flow source allows its users to fetch quotes and swap tokens via its DFlow auctions. An endorsement request returns an endorsement object containing a digital signature from your endorsement private key, which can be any Ed25519 keypair.

## Run using Docker
This repository contains a Dockerfile that can be used to build a Docker image for the endorsement server. The image is published to the github container registry at ghcr.io/dflowprotocol/endorsement-server:latest.

#### Get the Docker image
```console
$ docker pull ghcr.io/dflowprotocol/endorsement-server:latest
```
Alternatively, you can build the Docker image by running the following from the root of the repository:
```console
$ docker build --tag ghcr.io/dflowprotocol/endorsement-server:latest .
```

#### Generate an endorsement key
In this example, we write the endorsement key to the host's file system at `$(pwd)/endorsement-server-config/endorsementKey.json`.
```console
$ mkdir endorsement-server-config
$ docker run --mount type=bind,source=$(pwd)/endorsement-server-config,target=/app/config/ \
    ghcr.io/dflowprotocol/endorsement-server:latest keygen --path /app/config/endorsementKey.json
```

#### Run the endorsement server
In this example, we run the endorsement server using the endorsement key generated in the previous step.
```console
$ docker run -itp 8082:8082 \
    --mount type=bind,source=$(pwd)/endorsement-server-config,target=/app/config/ \
    ghcr.io/dflowprotocol/endorsement-server:latest start --endorsement-key-path /app/config/endorsementKey.json
```

## Endorsement Server API
### GET /endorsement

#### Request
Specify the retail trader's wallet address as a query parameter in your request.
##### cURL
```console
curl --location 'localhost:8082/endorsement?retailTrader=0x7251a7e0664FBB7691cA5951eD2B2A340Da07175'
```

##### TypeScript
```ts
// Use your endorsement server's URL
const endorsementServerURL = "http://localhost:8082/endorsement";
const walletAddress = "0x7251a7e0664FBB7691cA5951eD2B2A340Da07175";
const endorsementURL = endorsementServerURL + "?retailTrader=" + walletAddress;
const endorsement = await(await fetch(endorsementURL)).json();
```

#### Response
The response contains the following endorsement object that your client code will include when making a quote request or `sendTransaction` request via the DFlow Swap API. The DFlow network will verify that the request is properly endorsed if it is routed via an order flow auction.

```jsonc
{
  // Base58-encoded endorsement key public key used to sign the endorsement message
  "endorser": "string",
  // Base64-encoded Ed25519 signature of "{id},{expirationTime}" or "{id},{expirationTime},{retailTrader}"
  "signature": "string",
  // Unique identifier for the endorsement
  "id": "string",
  // Expiration time as UTC. Number of seconds since Jan 1, 1970 00:00:00 UTC.
  "expirationTimeUTC": "integer"
}
```

## Configuration
The following walks through the endorsement server's various configuration options. These configuration options can be set via the endorsement server's CLI, by using a config file, or via environment variables. Options specified via the CLI take precedence over options specified in a config file. Options specified via environment variables take least precedence.

| CLI option | Config file field | Environment variable | Type | Description |
| - | - | - | - | - |
| `--config` | | | string | Path to the config file |
| `--endorsement-key-path` | `endorsementKeyPath` | | string | Path to the endorsement key file |
| | | `ENDORSEMENT_KEY` | string | Endorsement private key as a JSON string |
| `--expiration-in-seconds` | `expirationInSeconds` | | integer | Each endorsement expires this many seconds after it is issued |
| `--server.*` | `server` | | object | Server configuration options including port, CORS allowed origin, and HTTP keep alive timeout |

#### Example config file
```json
{
    "endorsementKeyPath": "endorsementKey.json",
    "expirationInSeconds": 60,
    "server": {
        "port": 8082,
        "cors": {
            "origin": "*"
        },
        "keepAliveTimeout": 120
    }
}
```

## Run using Node.js
While we recommend using Docker to run the endorsement server, it can also be run using Node.js and Yarn.

#### Install dependencies
From the root of the repository, run:
```console
$ yarn install
```

#### Build the project using Yarn
From the root of the repository, run:
```console
$ yarn build
```

#### Change to the endorsement-server directory
From the root of the repository, run:
```console
$ cd @dflow-protocol/endorsement-server
```

#### Generate an endorsement key
From the @dflow-protocol/endorsement-server directory, run:
```console
$ yarn keygen
```

#### Run the endorsement server
In this example, we run the endorsement server using the endorsement key generated in the previous step. From the @dflow-protocol/endorsement-server directory, run:
```console
$ yarn start --endorsement-key-path endorsemenKey.json
```

## Run in development mode using Node.js
The endorsement server can be run in development mode using Node.js and Yarn. When running in development mode, the endorsement server will automatically restart when changes are made to the source code in @dflow-protocol/endorsement-server. In this mode, the endorsement server will use the `dev-config.json` file. Note that the endorsement server will only auto-restart when files in @dflow-protocol/endorsement-server change. If you make a change to @dflow-protocol/endorsement-client-lib, you need to rerun `yarn build` from the root of the repository.

#### Install dependencies
From the root of the repository, run:
```console
$ yarn install
```

#### Build the project using Yarn
From the root of the repository, run:
```console
$ yarn build
```

#### Change to the endorsement-server directory
From the root of the repository, run:
```console
$ cd @dflow-protocol/endorsement-server
```

#### Generate an endorsement key
From the @dflow-protocol/endorsement-server directory, run:
```console
$ yarn keygen
```

#### Run the endorsement server in development mode
From the @dflow-protocol/endorsement-server directory, run:
```console
$ yarn start:dev
```

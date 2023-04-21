### Docker Compose local networks

#### Prerequisites
- Install [Docker](https://www.docker.com/)

#### Build and run the localnet
The first time you run the localnet, **and any time source code for the services in the localnet has changed**, run with the `--build` flag.
```
docker compose up --build
```

#### Stop the localnet
```
docker compose down
```

#### Restart the localnet
```
docker compose down && docker compose up
```

#### Run a different localnet
There are currently four different local networks defined:
- `docker-compose.yml`
  - The main local network. Runs by default.

#### Run the dashboard against localnet
You'll need to set up a Keplr wallet and a Solana wallet to use the dashboard.
1. Install the Keplr wallet browser extension
    - [For Chrome](https://chrome.google.com/webstore/detail/keplr/dmkamcknogkgcdfhhbddcghachkejeap?hl=en)
2. Install a Solana wallet browser extension. Solflare is the best option.
    - [For Chrome](https://chrome.google.com/webstore/detail/solflare-wallet/bhhhlbepdkbapadjdnnojkbgioiodbic)
3. Import the order flow source's DFlow key into your Keplr wallet
    - Mnemonic is located at `install/dflow/ofs-1/mnemonic.txt`
4. Import the order flow source's Solana key into your Solana wallet
    - Private key is located at `install/solana/keypair/orderFlowSource.json`

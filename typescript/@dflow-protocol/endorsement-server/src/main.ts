import fs from "fs";
import process from "process";
import { Command, Option } from "commander";
import { endorsementServerConfig } from "./config";
import { EndorsementAPIContext } from "./context";
import { RequestEndorser } from "./requestEndorser";
import { EndorsementServer } from "./server";
import nacl from "tweetnacl";

async function main(opts: any): Promise<void> {
    const rawConfig = JSON.parse(fs.readFileSync(opts.config, "utf-8"));
    const config = endorsementServerConfig.parse(rawConfig);

    const keypairPath = config.endorsementKeyPath;
    const rawSecretKey = JSON.parse(fs.readFileSync(keypairPath, "utf-8"));
    const keypair = nacl.sign.keyPair.fromSecretKey(new Uint8Array(rawSecretKey));

    const requestEndorser = new RequestEndorser(keypair);
    const context = new EndorsementAPIContext(requestEndorser, config);
    const server = new EndorsementServer(context);

    const port = config.server?.port ?? 8082;
    server.listen(port, {
        callback: () => {
            const serverStartMsg = "Express server started on port: ";
            context.logger.info(serverStartMsg + port);
        },
        keepAliveTimeout: (config.server?.keepAliveTimeout ?? 5) * 1_000,
    });

    await waitForever();
}

async function waitForever(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
        await new Promise(resolve => setTimeout(resolve, 10 * 60_000));
    }
}

const program = new Command()
    .addOption(new Option("--config <CONFIG PATH>", "Config file path")
        .makeOptionMandatory())
    .addHelpText("before", "DFlow Endorsement Server\n")
    .showHelpAfterError()
    .parse();
const opts = program.opts();

main(opts).then(
    () => process.exit(0),
    error => {
        console.error(error);
        process.exit(1);
    },
);

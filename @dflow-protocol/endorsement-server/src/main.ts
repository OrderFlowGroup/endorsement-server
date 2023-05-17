import fs from "fs";
import process from "process";
import { Command, Option } from "commander";
import dotenv from "dotenv";
import yaml from "js-yaml";
import nacl from "tweetnacl";
import {
    EndorsementServerConfig,
    EndorsementServerConfigFile,
    endorsementServerConfigFile,
} from "./config";
import { EndorsementServerContext } from "./context";
import { RequestEndorser } from "./requestEndorser";
import { EndorsementServer } from "./server";

async function main(opts: any): Promise<void> {
    dotenv.config();

    let configFile: EndorsementServerConfigFile | undefined;
    if (opts.config !== undefined) {
        const rawConfigFile = yaml.load(fs.readFileSync(opts.config, "utf-8"));
        configFile = endorsementServerConfigFile.parse(rawConfigFile);
    }

    let endorsementKey: nacl.SignKeyPair;
    if (opts.endorsementKeyPath !== undefined) {
        const keyPath = opts.endorsementKeyPath;
        if (!fs.existsSync(keyPath)) {
            logAndExit(`Endorsement key path ${keyPath} from CLI does not exist`);
        }
        endorsementKey = parseEndorsementKey(fs.readFileSync(keyPath, "utf-8"));
    } else if (configFile?.endorsementKeyPath !== undefined) {
        const keyPath = configFile.endorsementKeyPath;
        if (!fs.existsSync(keyPath)) {
            logAndExit(`Endorsement key path ${keyPath} from config file does not exist`);
        }
        endorsementKey = parseEndorsementKey(fs.readFileSync(keyPath, "utf-8"));
    } else if (process.env.ENDORSEMENT_KEY !== undefined) {
        endorsementKey = parseEndorsementKey(process.env.ENDORSEMENT_KEY);
    } else {
        logAndExit(
            "Endorsement key not provided via CLI, config file, or ENDORSEMENT_KEY environment"
            + " variable. You must specify an endorsement key using one of the above methods."
        );
    }

    const expirationInSeconds = opts.expirationInSeconds !== undefined
        ? parseInt(opts.expirationInSeconds)
        : configFile?.expirationInSeconds
        ?? 120
    if (expirationInSeconds < 5) {
        logAndExit("Endorsement expiration must be at least 5 seconds");
    } else if (expirationInSeconds > 120) {
        logAndExit("Endorsement expiration must be at most 120 seconds");
    }

    const disablePaymentInLieuApproval = opts.disablePaymentInLieuApproval !== undefined
        ? opts.disablePaymentInLieuApproval
        : configFile?.disablePaymentInLieuApproval
        ?? false;

    const port = opts["server.port"] ?? configFile?.server?.port ?? 8082;
    const corsOrigin = opts["server.cors.origin"] ?? configFile?.server?.cors?.origin;
    const keepAliveTimeout = opts["server.keep-alive-timeout"]
        ?? configFile?.server?.keepAliveTimeout
        ?? 5;

    const config: EndorsementServerConfig = {
        endorsementKey,
        expirationInSeconds,
        disablePaymentInLieuApproval,
        server: {
            port,
            corsOrigin,
            keepAliveTimeout,
        }
    };

    const requestEndorser = new RequestEndorser(endorsementKey, expirationInSeconds);
    const context = new EndorsementServerContext(requestEndorser, config);
    const server = new EndorsementServer(context);

    server.listen({
        callback: () => {
            context.logger.info(`Endorsement server started on port ${port}`);
            context.logger.info(`Endorsement key: ${requestEndorser.base58PublicKey}`);
            context.logger.info(
                `Endorsement expiration: ${context.config.expirationInSeconds} seconds`
            );
            if (context.config.server.corsOrigin) {
                context.logger.info(`CORS origin: ${context.config.server.corsOrigin}`);
            }
        },
    });

    await waitForever();
}

async function waitForever(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
        await new Promise(resolve => setTimeout(resolve, 10 * 60_000));
    }
}

function logAndExit(msg: string): never {
    console.log(msg);
    process.exit(1);
}

function parseEndorsementKey(raw: string): nacl.SignKeyPair {
    try {
        const rawSecretKey = JSON.parse(raw);
        return nacl.sign.keyPair.fromSecretKey(new Uint8Array(rawSecretKey));
    } catch (error) {
        logAndExit(`Failed to parse endorsement key. ${error}`);
    }
}

const program = new Command()
    .addOption(new Option("--config <FILEPATH>", "Config filepath"))
    .addOption(new Option("--endorsement-key-path <FILEPATH>", "Endorsement key filepath"))
    .addOption(new Option(
        "--expiration-in-seconds <SECONDS>",
        "Each endorsement expires this many seconds after it is issued",
    ))
    .addOption(new Option(
        "--disable-payment-in-lieu-approval",
        "Disable payment in lieu approval endpoint",
    ))
    .addOption(new Option("--server.port <PORT>", "Port to listen on"))
    .addOption(new Option("--server.cors.origin <ORIGIN>", "CORS allowed origin"))
    .addOption(new Option("--server.keep-alive-timeout <SECONDS>", "Keep alive timeout in seconds"))
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

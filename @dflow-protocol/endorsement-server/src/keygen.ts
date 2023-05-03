import fs from "fs";
import path from "path";
import process from "process";
import bs58 from "bs58";
import { Command, Option } from "commander";
import nacl from "tweetnacl";

async function keygen(opts: any): Promise<void> {
    //get path from opts
    let keypairPath: string;
    if (opts.path === undefined) {
        keypairPath = "endorsementKey.json";
    } else {
        keypairPath = opts.path;
    }
    if (fs.existsSync(keypairPath) && !opts.force) {
        const absolutePath = path.resolve(keypairPath);
        console.log(`Refusing to overwrite ${absolutePath} without --force`);
        process.exit(1);
    }
    const seed = nacl.randomBytes(nacl.sign.seedLength);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);

    console.log("Generated public key: " + bs58.encode(keyPair.publicKey));
    console.log("Writing keypair to " + keypairPath);
    fs.writeFileSync(keypairPath, JSON.stringify(Array.from(keyPair.secretKey)), {
        mode: "600",
    });
}

const program = new Command()
    .addOption(new Option("--path <FILEPATH>", "output file path"))
    .addOption(new Option("--force", "Overwrite file if it already exists at the specified path"))
    .addHelpText("before", "DFlow Endorsement Server\n")
    .showHelpAfterError()
    .parse();
const opts = program.opts();

keygen(opts).then(
    () => process.exit(0),
    error => {
        console.error(error);
        process.exit(1);
    },
);

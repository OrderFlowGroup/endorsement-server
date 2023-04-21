import { EndorsementRequest } from "@dflow-protocol/endorsement-client-lib";
import bs58 from "bs58";
import { randomBytes } from "crypto";
import nacl from "tweetnacl";

export interface IRequestEndorser {
    readonly keypair: nacl.SignKeyPair
    readonly base58PublicKey: string
    maybeEndorse(request: EndorsementRequest): Promise<EndorseResult>
}

export type EndorseResult = ApprovedResult | RejectedResult

export type ApprovedResult = {
    approved: true
    endorsement: {
        signature: string
        id: string
        expirationTimeUTC: number
    }
}

export type RejectedResult = {
    approved: false
    reason: RejectReason
}

export enum RejectReason {
    RateLimitExceeded = 1,
}

export class RequestEndorser implements IRequestEndorser {
    readonly keypair: nacl.SignKeyPair;
    readonly base58PublicKey: string;

    constructor(keypair: nacl.SignKeyPair) {
        this.keypair = keypair;
        this.base58PublicKey = bs58.encode(this.keypair.publicKey);
    }

    async maybeEndorse(request: EndorsementRequest): Promise<EndorseResult> {
        const id = randomBytes(8).toString("base64");
        const now = new Date();
        const nowUTCSeconds = Math.floor(now.getTime() / 1000);
        const expirationTimeUTC = nowUTCSeconds + 60;
        const msg = request.retailTrader === undefined
            ? `${id},${expirationTimeUTC}`
            : `${id},${expirationTimeUTC},${request.retailTrader}`;
        const msgBuffer = Buffer.from(msg, "utf-8");
        const signatureBuffer = nacl.sign.detached(msgBuffer, this.keypair.secretKey);
        const signature = Buffer.from(signatureBuffer).toString("base64");
        return {
            approved: true,
            endorsement: {
                signature,
                id,
                expirationTimeUTC,
            },
        };
    }
}

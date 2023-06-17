import {
    EndorsementRequest,
    PaymentInLieuApprovalRequest,
} from "@dflow-protocol/endorsement-client-lib";
import {
    makeEndorsementData,
    makeEndorsementMessage,
    makePaymentInLieuMessage,
} from "@dflow-protocol/signatory-client-lib";
import bs58 from "bs58";
import { randomBytes } from "crypto";
import { InvalidEndorsementRequest } from "./error";
import nacl from "tweetnacl";

export type EndorseResult = EndorsedResult | NotEndorsedResult

export type EndorsedResult = {
    endorsed: true
    endorsement: {
        signature: string
        id: string
        expirationTimeUTC: number
        data: string
    }
}

export type NotEndorsedResult = {
    endorsed: false
    reason: NotEndorsedReason
}

export enum NotEndorsedReason {
    RateLimitExceeded = 1,
}

export type ApprovePaymentInLieuResult = PaymentInLieuApprovedResult | PaymentInLieuRejectedResult

export type PaymentInLieuApprovedResult = {
    approved: true
    approval: string
}

export type PaymentInLieuRejectedResult = {
    approved: false
    reason: PaymentInLieuRejectedReason
}

export enum PaymentInLieuRejectedReason {
    EndorsementExpired = 1,
    RateLimitExceeded = 2,
}

export class RequestEndorser {
    readonly keypair: nacl.SignKeyPair;
    readonly base58PublicKey: string;
    readonly expirationInSeconds: number;

    constructor(keypair: nacl.SignKeyPair, expirationInSeconds: number) {
        this.keypair = keypair;
        this.base58PublicKey = bs58.encode(this.keypair.publicKey);
        this.expirationInSeconds = expirationInSeconds;
    }

    async maybeEndorse(request: EndorsementRequest, now: Date): Promise<EndorseResult> {
        const id = randomBytes(8).toString("base64");
        const nowUTCSeconds = Math.floor(now.getTime() / 1000);
        const expirationTimeUTC = nowUTCSeconds + this.expirationInSeconds;

        const { platformFeeBps, platformFeeReceiver } = request;
        let platformFee;
        if (platformFeeBps !== undefined && platformFeeReceiver !== undefined) {
            const parsedPlatformFeeBps = tryParsePlatformFeeBps(platformFeeBps);
            if (parsedPlatformFeeBps === null) {
                throw new InvalidEndorsementRequest("invalid platformFeeBps");
            }
            platformFee = { bps: parsedPlatformFeeBps, receiver: platformFeeReceiver };
        } else if (platformFeeBps !== undefined) {
            throw new InvalidEndorsementRequest("platformFeeReceiver not specified");
        } else if (platformFeeReceiver !== undefined) {
            throw new InvalidEndorsementRequest("platformFeeBps not specified");
        }

        const endorsementData = makeEndorsementData({
            retailTrader: request.retailTrader,
            platformFee,
        });

        const msg = makeEndorsementMessage(id, expirationTimeUTC, endorsementData);

        const msgBuffer = Buffer.from(msg, "utf-8");
        const signatureBuffer = nacl.sign.detached(msgBuffer, this.keypair.secretKey);
        const signature = Buffer.from(signatureBuffer).toString("base64");

        return {
            endorsed: true,
            endorsement: {
                signature,
                id,
                expirationTimeUTC,
                data: endorsementData,
            },
        };
    }

    async maybeApprovePaymentInLieu(
        request: PaymentInLieuApprovalRequest,
        now: Date,
    ): Promise<ApprovePaymentInLieuResult> {
        const paymentInLieuToken = request.paymentInLieuToken;

        // Check that endorsement is not expired
        const endorsement = paymentInLieuToken.endorsement;
        const nowUTCSeconds = Math.floor(now.getTime() / 1000);
        const expirationTimeUTCSeconds = endorsement.expirationTimeUTC;
        if (nowUTCSeconds >= expirationTimeUTCSeconds) {
            return { approved: false, reason: PaymentInLieuRejectedReason.EndorsementExpired };
        }

        // Note that we don't verify DFlow node's signature of the payment in lieu token. The DFlow
        // node will not accept the approval if the token was tampered with.

        const approvalMessage = makePaymentInLieuMessage(paymentInLieuToken);
        const approvalMessageBuffer = Buffer.from(approvalMessage, "utf-8");
        const approvalSignatureBuffer = nacl.sign.detached(
            approvalMessageBuffer,
            this.keypair.secretKey,
        );
        const approvalSignature = Buffer.from(approvalSignatureBuffer).toString("base64");
        return {
            approved: true,
            approval: approvalSignature,
        };
    }
}

function tryParsePlatformFeeBps(raw: string): number | null {
    try {
        const parsed = Number(BigInt(raw));
        if (parsed < 0 || parsed > 5000) {
            return null;
        }
        return parsed;
    } catch {
        return null;
    }
}

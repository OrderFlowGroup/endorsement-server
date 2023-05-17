import {
    EndorsementRequest,
    PaymentInLieuApprovalRequest,
} from "@dflow-protocol/endorsement-client-lib";
import { makePaymentInLieuMessage } from "@dflow-protocol/signatory-client-lib";
import bs58 from "bs58";
import { randomBytes } from "crypto";
import nacl from "tweetnacl";

export type EndorseResult = EndorsedResult | NotEndorsedResult

export type EndorsedResult = {
    endorsed: true
    endorsement: {
        signature: string
        id: string
        expirationTimeUTC: number
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
        const msg = request.retailTrader === undefined
            ? `${id},${expirationTimeUTC}`
            : `${id},${expirationTimeUTC},${request.retailTrader}`;
        const msgBuffer = Buffer.from(msg, "utf-8");
        const signatureBuffer = nacl.sign.detached(msgBuffer, this.keypair.secretKey);
        const signature = Buffer.from(signatureBuffer).toString("base64");
        return {
            endorsed: true,
            endorsement: {
                signature,
                id,
                expirationTimeUTC,
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

        const approvalMessage = paymentInLieuToken.signature;
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

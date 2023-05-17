import { schemaEndorsement, schemaPaymentInLieuToken } from "@dflow-protocol/signatory-client-lib";
import { z } from "zod";

export type EndorsementRequest = z.infer<typeof schemaEndorsementRequest>;
export const schemaEndorsementRequest = z.object({
    /** Public key of the retail trader's wallet on the settlement network, encoded using the
     *  encoding scheme used for wallet addresses on the settlement network. */
    retailTrader: z.optional(z.string()),
});

export type EndorsementResponse = z.infer<typeof schemaEndorsementResponse>;
export const schemaEndorsementResponse = schemaEndorsement;

export type PaymentInLieuApprovalRequest = z.infer<typeof schemaPaymentInLieuApprovalRequest>;
export const schemaPaymentInLieuApprovalRequest = z.object({
    paymentInLieuToken: schemaPaymentInLieuToken,
});

export type PaymentInLieuApprovalResponse = z.infer<typeof schemaPaymentInLieuApprovalResponse>;
export const schemaPaymentInLieuApprovalResponse = z.object({
    /** Base58-encoded Ed25519 public key used to sign the approval message. */
    approver: z.string(),
    /** Approver's Base64-encoded approval signature of `paymentInLieuToken.signature` */
    approval: z.string(),
});

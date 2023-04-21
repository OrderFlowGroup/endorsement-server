import { schemaEndorsement } from "@dflow-protocol/signatory-client-lib";
import { z } from "zod";

export enum ResponseCode {
    EndorsementOk = 0,
    RateLimitExceeded = 10,
    InvalidRequest = 11,
}

export type EndorsementRequest = z.infer<typeof schemaEndorsementRequest>;
export const schemaEndorsementRequest = z.object({
    /** Public key of the retail trader's target chain wallet, encoded using the
     *  encoding scheme used for the target chain. */
    retailTrader: z.optional(z.string()),
});

export type EndorsementResponseRateLimitExceeded
    = z.infer<typeof schemaEndorsementResponseRateLimitExceeded>;
export const schemaEndorsementResponseRateLimitExceeded = z.object({
    code: z.literal(ResponseCode.RateLimitExceeded),
});

export type EndorsementResponseInvalidRequest
    = z.infer<typeof schemaEndorsementResponseInvalidRequest>;
export const schemaEndorsementResponseInvalidRequest = z.object({
    code: z.literal(ResponseCode.InvalidRequest),
});

export type EndorsementErrorResponse = z.infer<typeof schemaEndorsementErrorResponse>;
export const schemaEndorsementErrorResponse = z.union([
    schemaEndorsementResponseRateLimitExceeded,
    schemaEndorsementResponseInvalidRequest,
]);

export type EndorsementOkResponse = z.infer<typeof schemaEndorsementOkResponse>;
export const schemaEndorsementOkResponse = z.object({
    code: z.literal(ResponseCode.EndorsementOk),
    endorsement: schemaEndorsement,
});

export type EndorsementResponse = z.infer<typeof schemaEndorsementResponse>;
export const schemaEndorsementResponse = z.union([
    schemaEndorsementOkResponse,
    schemaEndorsementErrorResponse,
]);

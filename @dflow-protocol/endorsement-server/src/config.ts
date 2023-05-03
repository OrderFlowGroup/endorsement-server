import nacl from "tweetnacl";
import { z } from "zod";

export type EndorsementServerConfigFile = z.infer<typeof endorsementServerConfigFile>;
export const endorsementServerConfigFile = z.object({
    /** Endorsement key file path */
    endorsementKeyPath: z.optional(z.string()),

    /** Each endorsement expires this many seconds after it is issued */
    expirationInSeconds: z.optional(z.number().int().positive()),

    /** Optional server settings */
    server: z.optional(z.object({
        /** Server port */
        port: z.optional(z.number().int().positive()),
        /** CORS settings */
        cors: z.optional(z.object({
            origin: z.string(),
        })),
        /** Keep alive timeout in seconds */
        keepAliveTimeout: z.optional(z.number().positive()),
    })),
});

export type EndorsementServerConfig = {
    endorsementKey: nacl.SignKeyPair
    expirationInSeconds: number
    server: {
        port: number
        corsOrigin?: string
        keepAliveTimeout: number
    }
}

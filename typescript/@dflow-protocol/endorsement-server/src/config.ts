import { z } from "zod";

export type EndorsementServerConfig = z.infer<typeof endorsementServerConfig>;
export const endorsementServerConfig = z.object({
    /** Endorsement key file path */
    endorsementKeyPath: z.string(),

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

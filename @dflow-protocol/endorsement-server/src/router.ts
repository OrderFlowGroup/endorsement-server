import {
    endorsementPath,
    EndorsementRequest,
    EndorsementResponse,
    endorsementKeyPath,
    healthCheckPath,
    ResponseCode,
    schemaEndorsementRequest,
} from "@dflow-protocol/endorsement-client-lib";
import { Request, Response, Router } from "express";
import { EndorsementServerContext } from "./context";
import { RejectReason } from "./requestEndorser";

export class EndorsementAPIRouter {
    readonly context: EndorsementServerContext;
    readonly router: Router;

    constructor(context: EndorsementServerContext) {
        this.context = context;
        this.router = Router();

        this.healthCheck = this.healthCheck.bind(this);
        this.router.get(healthCheckPath, this.healthCheck);

        this.getEndorsement = this.getEndorsement.bind(this);
        this.router.get(endorsementPath, this.getEndorsement);
        this.getEndorsementKey = this.getEndorsementKey.bind(this);
        this.router.get(endorsementKeyPath, this.getEndorsementKey);
    }

    async healthCheck(_req: Request, res: Response): Promise<Response> {
        return res.json("healthy");
    }

    async getEndorsement(
        req: Request,
        res: Response<EndorsementResponse>,
    ): Promise<Response<EndorsementResponse>> {
        const args = this.parseEndorsementRequest(req.query);
        if (args === null) {
            return res.json({
                code: ResponseCode.InvalidRequest,
            });
        }

        const result = await this.context.requestEndorser.maybeEndorse(args);
        if (result.approved) {
            return res.json({
                code: ResponseCode.EndorsementOk,
                endorsement: {
                    endorser: this.context.requestEndorser.base58PublicKey,
                    signature: result.endorsement.signature,
                    id: result.endorsement.id,
                    expirationTimeUTC: result.endorsement.expirationTimeUTC,
                },
            });
        }

        switch (result.reason) {
            case RejectReason.RateLimitExceeded: {
                return res.json({
                    code: ResponseCode.RateLimitExceeded,
                });
            }
            default: {
                throw new Error(`Unrecognized RejectReason ${RejectReason[result.reason]}`)
            }
        }
    }

    parseEndorsementRequest(query: any): EndorsementRequest | null {
        try {
            return schemaEndorsementRequest.parse(query);
        } catch {
            return null;
        }
    }

    async getEndorsementKey(req: Request, res: Response) {
        return res.json({
            publicKey: this.context.requestEndorser.base58PublicKey,
        });
    }
}

import {
    endorsementPath,
    EndorsementRequest,
    EndorsementResponse,
    endorsementKeyPath,
    healthCheckPath,
    schemaEndorsementRequest,
    paymentInLieuApprovalPath,
    PaymentInLieuApprovalResponse,
    PaymentInLieuApprovalRequest,
    schemaPaymentInLieuApprovalRequest,
} from "@dflow-protocol/endorsement-client-lib";
import { Request, Response, Router } from "express";
import { EndorsementServerContext } from "./context";
import {
    EndorsementExpired,
    InvalidEndorsementRequest,
    InvalidPaymentInLieuApprovalRequest,
    RateLimitExceeded,
} from "./error";
import { NotEndorsedReason, PaymentInLieuRejectedReason } from "./requestEndorser";

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

        if (context.config.disablePaymentInLieuApproval !== true) {
            this.paymentInLieuApproval = this.paymentInLieuApproval.bind(this);
            this.router.post(paymentInLieuApprovalPath, this.paymentInLieuApproval);
        }
    }

    async healthCheck(_req: Request, res: Response): Promise<Response> {
        return res.json("healthy");
    }

    async getEndorsement(
        req: Request,
        res: Response<EndorsementResponse>,
    ): Promise<Response<EndorsementResponse>> {
        let args: EndorsementRequest;
        try {
            args = schemaEndorsementRequest.parse(req.query);
        } catch (error) {
            throw new InvalidEndorsementRequest(error);
        }
        const now = new Date();
        const requestEndorser = this.context.requestEndorser;

        const result = await requestEndorser.maybeEndorse(args, now);
        if (result.endorsed) {
            const endorsement = result.endorsement;
            return res.json({
                endorser: requestEndorser.base58PublicKey,
                signature: endorsement.signature,
                id: endorsement.id,
                expirationTimeUTC: endorsement.expirationTimeUTC,
                data: endorsement.data,
            });
        }

        switch (result.reason) {
            case NotEndorsedReason.RateLimitExceeded: {
                throw new RateLimitExceeded();
            }
            default: {
                const _exhaustiveCheck: never = result.reason;
                throw new Error(`Unrecognized RejectReason ${NotEndorsedReason[result.reason]}`);
            }
        }
    }

    async getEndorsementKey(_req: Request, res: Response) {
        return res.json({ publicKey: this.context.requestEndorser.base58PublicKey });
    }

    async paymentInLieuApproval(
        req: Request,
        res: Response<PaymentInLieuApprovalResponse>,
    ): Promise<Response<PaymentInLieuApprovalResponse>> {
        let args: PaymentInLieuApprovalRequest;
        try {
            args = schemaPaymentInLieuApprovalRequest.parse(req.body);
        } catch (error) {
            throw new InvalidPaymentInLieuApprovalRequest(error);
        }
        const now = new Date();

        const result = await this.context.requestEndorser.maybeApprovePaymentInLieu(args, now);
        if (result.approved) {
            return res.json({
                approver: this.context.requestEndorser.base58PublicKey,
                approval: result.approval,
            });
        }

        switch (result.reason) {
            case PaymentInLieuRejectedReason.EndorsementExpired: {
                throw new EndorsementExpired();
            }
            case PaymentInLieuRejectedReason.RateLimitExceeded: {
                throw new RateLimitExceeded();
            }
            default: {
                const _exhaustiveCheck: never = result.reason;
                throw new Error(
                    `Unrecognized RejectReason ${PaymentInLieuRejectedReason[result.reason]}`
                );
            }
        }
    }
}

import HttpStatusCodes from "http-status-codes";


export abstract class CustomError extends Error {
    public readonly HttpStatus = HttpStatusCodes.BAD_REQUEST;

    constructor(msg: string, httpStatus: number) {
        super(msg);
        this.HttpStatus = httpStatus;
    }
}

export class InvalidEndorsementRequest extends CustomError {
    public static readonly Msg = "Invalid endorsement request";
    public static readonly HttpStatus = HttpStatusCodes.BAD_REQUEST;

    constructor(inner: Error | string) {
        const errorMsg = inner instanceof Error ? inner.message : inner;
        super(
            `${InvalidEndorsementRequest.Msg}: ${errorMsg}`,
            InvalidEndorsementRequest.HttpStatus,
        );
    }
}

export class RateLimitExceeded extends CustomError {
    public static readonly Msg = "Rate limit exceeded";
    public static readonly HttpStatus = HttpStatusCodes.TOO_MANY_REQUESTS;

    constructor() {
        super(RateLimitExceeded.Msg, RateLimitExceeded.HttpStatus);
    }
}

export class InvalidPaymentInLieuApprovalRequest extends CustomError {
    public static readonly Msg = "Invalid payment in lieu approval request";
    public static readonly HttpStatus = HttpStatusCodes.BAD_REQUEST;

    public static makeMessage(error: Error) {
        return `${this.Msg}. ${error}`;
    }

    constructor(error: Error) {
        super(
            InvalidPaymentInLieuApprovalRequest.makeMessage(error),
            InvalidPaymentInLieuApprovalRequest.HttpStatus,
        );
    }
}

export class EndorsementExpired extends CustomError {
    public static readonly Msg = "Endorsement expired";
    public static readonly HttpStatus = HttpStatusCodes.BAD_REQUEST;

    constructor() {
        super(EndorsementExpired.Msg, EndorsementExpired.HttpStatus);
    }
}

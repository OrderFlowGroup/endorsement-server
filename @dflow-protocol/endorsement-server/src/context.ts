import { EndorsementServerConfig } from "./config";
import { Logger } from "./logger";
import { RequestEndorser } from "./requestEndorser";

export class EndorsementServerContext {
    readonly requestEndorser: RequestEndorser
    readonly config: EndorsementServerConfig
    readonly logger: Logger

    constructor(requestEndorser: RequestEndorser, config: EndorsementServerConfig) {
        this.requestEndorser = requestEndorser;
        this.config = config;
        this.logger = new Logger();
    }
}

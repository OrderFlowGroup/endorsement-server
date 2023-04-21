import { EndorsementServerConfig } from "./config";
import { Logger } from "./logger";
import { IRequestEndorser } from "./requestEndorser";

export class EndorsementAPIContext {
    readonly requestEndorser: IRequestEndorser
    readonly config: EndorsementServerConfig
    readonly logger: Logger

    constructor(requestEndorser: IRequestEndorser, config: EndorsementServerConfig) {
        this.requestEndorser = requestEndorser;
        this.config = config;
        this.logger = new Logger();
    }
}

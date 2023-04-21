import { apiBasePath } from "@dflow-protocol/endorsement-client-lib";
import cors from "cors";
import express, { Express, NextFunction, Request, Response } from "express";
import "express-async-errors";
import helmet from "helmet";
import http from "http";
import StatusCodes from "http-status-codes";
import morgan from "morgan";
import { EndorsementAPIContext } from "./context";
import { EndorsementAPIRouter } from "./router";

export class EndorsementServer {
    readonly app: Express;
    listeningServer: http.Server | undefined;

    constructor(context: EndorsementAPIContext) {
        this.app = express();
        this.app.use(express.json());
        this.app.use(express.urlencoded({extended: true}))
        this.app.use(morgan("combined"))
        this.app.use(helmet());
        if (context.config.server?.cors) {
            this.app.use(cors({
                origin: context.config.server.cors.origin,
            }));
        }

        const endorsementAPI = new EndorsementAPIRouter(context);
        this.app.use(apiBasePath, endorsementAPI.router);

        this.app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
            context.logger.error(err);
            const status = StatusCodes.BAD_REQUEST;
            return res.status(status).json({
                error: err.message,
            });
        });
    }

    listen(port: number, opts?: ListenOpts) {
        this.listeningServer = this.app.listen(port, opts?.callback);
        if (opts?.keepAliveTimeout !== undefined) {
            this.listeningServer.keepAliveTimeout = opts.keepAliveTimeout;
        }
    }

    stop() {
        this.listeningServer?.close();
    }
}

type ListenOpts = {
    callback?: () => void
    /** HTTP keep-alive timeout in milliseconds */
    keepAliveTimeout?: number
}

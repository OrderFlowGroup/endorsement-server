import { apiBasePath } from "@dflow-protocol/endorsement-client-lib";
import cors from "cors";
import express, { Express, NextFunction, Request, Response } from "express";
import "express-async-errors";
import helmet from "helmet";
import http from "http";
import StatusCodes from "http-status-codes";
import morgan from "morgan";
import { EndorsementServerContext } from "./context";
import { EndorsementAPIRouter } from "./router";

export class EndorsementServer {
    readonly context: EndorsementServerContext;
    readonly app: Express;
    listeningServer: http.Server | undefined;

    constructor(context: EndorsementServerContext) {
        this.context = context;
        this.app = express();
        this.app.use(express.json());
        this.app.use(express.urlencoded({extended: true}))
        this.app.use(morgan("combined"))
        this.app.use(helmet());
        if (context.config.server.corsOrigin) {
            this.app.use(cors({
                origin: context.config.server.corsOrigin,
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

    listen(opts?: ListenOpts) {
        const port = this.context.config.server.port;
        const keepAliveTimeout = this.context.config.server.keepAliveTimeout;
        this.listeningServer = this.app.listen(port, opts?.callback);
        this.listeningServer.keepAliveTimeout = keepAliveTimeout * 1_000;
    }

    stop() {
        this.listeningServer?.close();
    }
}

type ListenOpts = {
    callback?: () => void
}

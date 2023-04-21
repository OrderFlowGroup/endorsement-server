# BUILD: docker build --tag endorsement-server:latest --file @dflow-protocol/endorsement-server/Dockerfile .
# RUN:
# docker run -itp 8082:8082 \
#     --mount type=bind,source=/Users/jeffdelonge/git/validator/install/endorsement-server/config.json,target=/config/config.json \
#     --mount type=bind,source=/Users/jeffdelonge/git/validator/install/dflow/ofs-1/endsMtTJP7W4cHe2szQ4DUTvW9xdtTXtBGtscgXsGsK.json,target=/key/flow-endorsement.json \
#     endorsement-server:latest yarn start --config /config/config.json


FROM node:18 as pruner
WORKDIR /typescript
RUN yarn global add turbo@1.6.1
COPY . .
RUN turbo prune --scope @dflow-protocol/endorsement-server --docker


FROM node:18 as builder
WORKDIR /typescript
COPY nx.json .
COPY --from=pruner /typescript/out/json/ .
COPY --from=pruner /typescript/out/yarn.lock .
RUN yarn install
COPY --from=pruner /typescript/out/full/ .
COPY ts-client ts-client
RUN yarn build --projects @dflow-protocol/endorsement-server


FROM node:18-alpine as runner
RUN addgroup --system --gid 1001 containeruser
RUN adduser --system --uid 1001 containeruser
USER containeruser:containeruser
COPY --from=builder /typescript/@dflow-protocol /typescript/@dflow-protocol
COPY --from=builder /typescript/node_modules /typescript/node_modules

WORKDIR /typescript/@dflow-protocol/endorsement-server
EXPOSE 8082
CMD ["yarn", "start"]

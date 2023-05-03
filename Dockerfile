FROM node:18 as builder
WORKDIR /app
COPY nx.json .
COPY package.json .
COPY yarn.lock .
COPY @dflow-protocol @dflow-protocol
RUN yarn install
RUN yarn build

FROM node:18-alpine as runner
RUN addgroup --system --gid 1001 containeruser
RUN adduser --system --uid 1001 containeruser
USER containeruser:containeruser
COPY --from=builder /app/@dflow-protocol /app/@dflow-protocol
COPY --from=builder /app/node_modules /app/node_modules
WORKDIR /app/@dflow-protocol/endorsement-server
EXPOSE 8082
ENTRYPOINT ["yarn"]
CMD ["start", "--help"]

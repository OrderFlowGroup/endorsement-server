# docker build --tag endorsement-server:latest .

FROM rust:1.70.0-slim-buster as build

# install build dependencies
RUN apt-get update
RUN apt-get install pkg-config libssl-dev -y

# create a new empty shell project
RUN USER=root cargo new --bin endorsement-server
WORKDIR /endorsement-server

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/endorsement_server*
RUN cargo build --release

# our final base
FROM gcr.io/distroless/cc as runner

# copy the build artifact from the build stage
COPY --from=build /endorsement-server/target/release/endorsement-server .

STOPSIGNAL SIGINT

# set the startup command to run your binary
ENTRYPOINT ["./endorsement-server"]

# Multi-stage with a distroless final image: this service's
# whole reason for existing is holding a credential, so a minimal final image
# with no shell and no package manager is a security property worth the extra
# stage (auth-design.md: "a small dependency tree is a security argument
# rather than a taste one here"). CGO_ENABLED=0 works cleanly because
# modernc.org/sqlite is a pure-Go SQLite implementation — no CGO toolchain
# needed in the build image.
FROM golang:1.22-alpine AS build

WORKDIR /auth-service

COPY ./src/go.mod ./src/go.sum ./
RUN go mod download

COPY ./src .
RUN CGO_ENABLED=0 go build -o main .

FROM gcr.io/distroless/static-debian12

ENV SQLITE_DB_PATH=/data/auth.db

EXPOSE 80
VOLUME ["/data"]

COPY --from=build /auth-service/main /main

ENTRYPOINT ["/main"]

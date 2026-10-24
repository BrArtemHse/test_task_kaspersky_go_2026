FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=65532:65532 /out/server /app/server
COPY --chown=65532:65532 data-placeholder/ /data/
ENV HTTP_ADDR=:8080 DB_PATH=/data/threats.db
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/server"]

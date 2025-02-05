FROM golang:1.23-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=`go env GOHOSTOS` GOARCH=`go env GOHOSTARCH` go build -o out/server -ldflags="-w -s" .

FROM alpine:latest
COPY --from=builder /app/out/server /app/server
WORKDIR /app
CMD ["./server"]
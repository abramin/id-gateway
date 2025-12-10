FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY main.go ./
RUN go build -o resource-server

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/resource-server ./resource-server
EXPOSE 9000
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app
USER app
CMD ["./resource-server"]

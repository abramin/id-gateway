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
CMD ["./resource-server"]

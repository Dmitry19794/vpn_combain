# Stage 1: сборка
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o checker .

# Stage 2: мини-образ
FROM scratch
COPY --from=builder /app/checker /checker
ENTRYPOINT ["/checker"]
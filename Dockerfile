FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN apk add --no-cache git
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/ca-server ./cmd/server

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /bin/ca-server /bin/ca-server
COPY migrations /app/migrations
EXPOSE 8080
ENTRYPOINT ["/bin/ca-server"]

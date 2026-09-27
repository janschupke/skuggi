FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /ledgerline .

FROM alpine:3.20
WORKDIR /app
COPY --from=build /ledgerline /app/ledgerline
COPY data ./data
COPY static ./static
EXPOSE 8080
CMD ["/app/ledgerline"]

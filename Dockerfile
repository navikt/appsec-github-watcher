FROM cgr.dev/chainguard/go:latest AS builder
ARG APP
ENV GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE=on
COPY . /src
WORKDIR /src
RUN go mod download
RUN go build -a -installsuffix cgo -o /bin/app ./cmd/$APP

FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --from=builder /bin/app /app/app
ENTRYPOINT ["/app/app"]
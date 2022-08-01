FROM golang:1.18.5 as builder

COPY . /go/src/github.com/kong/go-echo

WORKDIR /go/src/github.com/kong/go-echo
RUN CGO_ENABLED=0 go build -o /go/bin/tcp-echo .

FROM gcr.io/distroless/static-debian11

COPY --from=builder /go/bin/tcp-echo /tcp-echo

WORKDIR /

ENTRYPOINT ["/tcp-echo"]

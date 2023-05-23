# go-echo

This repo is a fork of <https://github.com/cjimti/go-echo> maintained by Kong. The main purpose of this fork is to have multi-arch images with both amd64 and arm64 support.

It adds UDP and HTTP echo services in addition to the original TCP and TLS services.

## Quick Start Guide

Run `go-echo` to start a echo server for different protocols, with ports configurable via environment variables

- `TCP`  on port `1025` adjustable with `TCP_PORT`
- `UDP`  on port `1026` adjustable with `UDP_PORT`
- `HTTP` on port `1027` adjustable with `HTTP_PORT`

In order to run the server as a TLS server, set `TLS_PORT` to the port to listen on, `TLS_CA_CERT_FILE` to path of CA certificate file, `TLS_CERT_FILE` and `TLS_KEY_FILE` to paths of certificate-key pair.

`go-echo` returns additional info in the form of the below message when specific environment variables are
explicitly set

```sh
Welcome, you are connected to node ${NODE_NAME}.
Running on Pod ${POD_NAME}.
In namespace ${POD_NAMESPACE}.
With IP address ${POD_IP}.
Service account ${SERVICE_ACCOUNT}.
```

when a variable is omitted, line with a message is omitted too.

Check [example_deploy.yaml](./example_deploy.yaml) for an example usage with Kubernetes.

## Release procedure

To have a new image version, one needs to create a new Github release, and the new Docker image will be automatically built and pushed. The release has to be created manually, as there is no release automation in place.

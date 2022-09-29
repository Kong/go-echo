# go-echo

This repo is a fork of https://github.com/cjimti/go-echo maintained by Kong. The main purpose of this fork is to have multi-arch images with both amd64 and arm64 support.

## Quick Start Guide

Run `go-echo` to start a TCP server listening port on 1025. The server will return a welcome message to the client and will echo what it received from client. Set environment variable `TCP_PORT` to configure a different port to listen on.

In order to run the server as a TLS server, set `TLS_PORT` to the port to listen on, `TLS_CA_CERT_FILE` to path of CA certificate file, `TLS_CERT_FILE` and `TLS_KEY_FILE` to paths of certificate-key pair.


## Release procedure

To have a new image version, one needs to create a new Github release, and the new Docker image will be automatically built and pushed. The release has to be created manually, as there is no release automation in place.

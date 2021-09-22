env GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CGO_LDFLAGS=-static CC=x86_64-linux-musl-gcc go build
scp okv5 root@ssr:okv5/eth/v5
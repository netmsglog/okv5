@echo off
set GOOS=linux
set GOARCH=amd64
echo set CGO_ENABLED=1
echo set CGO_LDFLAGS=-static
echo set CC=D:\musl\bin\gcc
go build
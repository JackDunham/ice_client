#!/bin/bash

env GOOS=darwin GOARCH=arm64 go build -o link_exchanger exchange.go

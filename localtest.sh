#!/bin/bash

mkdir -p dist
go build -o dist/iam-pb-check main.go
mkdir -p $HOME/local/bin
mv dist/iam-pb-check $HOME/local/bin/iam-pb-check

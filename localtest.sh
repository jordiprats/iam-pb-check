#!/bin/bash

mkdir -p dist
go build -o dist/ec2-pb-check main.go
mkdir -p $HOME/local/bin
mv dist/ec2-pb-check $HOME/local/bin/ec2-pb-check

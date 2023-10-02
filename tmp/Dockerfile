FROM golang:latest

RUN apt-get update
RUN apt-get upgrade -y

ENV GOBIN /go/bin

RUN git config --global --add url."https://${TOKEN}:x-oauth-basic@code.rbi.tech/".insteadOf "https://code.rbi.tech/" && go env -w GOPRIVATE="code.rbi.tech/*"

RUN go get code.rbi.tech/raiffeisen/ua-product-security-libs@v0.0.8

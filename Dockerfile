FROM golang:latest AS golang
WORKDIR /go/src/github.com/bitly/oauth2_proxy
RUN go get -u github.com/golang/dep/cmd/dep
COPY . .
#RUN dep ensure && \
RUN go get ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o oauth2_proxy .

FROM scratch
COPY --from=golang /go/src/github.com/bitly/oauth2_proxy/oauth2_proxy /
COPY --from=golang /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8080 4180
ENTRYPOINT ["/oauth2_proxy"]

FROM golang

ADD . /go/src/github.com/yahoo/bftkv

WORKDIR /go/src/github.com/yahoo/bftkv/scripts/run_docker

ENTRYPOINT ../run.sh

EXPOSE 5601-5606
EXPOSE 5701-5710
EXPOSE 5801-5810


#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..

DOCKER_IMAGE=${DOCKER_IMAGE:-kyanpay/kyand-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}

BUILD_DIR=${BUILD_DIR:-.}

rm docker/bin/*
mkdir docker/bin
cp $BUILD_DIR/src/kyand docker/bin/
cp $BUILD_DIR/src/kyan-cli docker/bin/
cp $BUILD_DIR/src/kyan-tx docker/bin/
strip docker/bin/kyand
strip docker/bin/kyan-cli
strip docker/bin/kyan-tx

docker build --pull -t $DOCKER_IMAGE:$DOCKER_TAG -f docker/Dockerfile docker

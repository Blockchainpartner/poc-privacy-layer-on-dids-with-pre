#!/usr/bin/env bash

set -e
echo "Starting Up PoC..."

# declare variables
COMPOSE_FILE="${0%/*}/nucypher/dev/docker/8-federated-ursulas-and-ipfs-host.yml"
DEMO_DIR="/code/examples/did_demo/"

# add PoC files to NuCypher repository
cp 8-federated-ursulas-and-ipfs-host.yml nucypher/dev/docker/
cp -r did_demo nucypher/examples/

# run some ursulas
docker-compose -f $COMPOSE_FILE up -d
echo "Wait for Ursula learning to occur"
sleep 5

# Run demo
echo "Starting Demo"
docker-compose -f $COMPOSE_FILE run -w $DEMO_DIR nucypher-dev python did-demo.py 172.28.1.3:11500 False

# tear it down
docker-compose -f $COMPOSE_FILE stop

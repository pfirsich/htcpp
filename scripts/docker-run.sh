#!/bin/bash
docker run --init --workdir /app -v "$(pwd):/app" --network=host htcpp "$@"

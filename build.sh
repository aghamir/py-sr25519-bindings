#!/bin/bash

# Build local OS wheelhouse
maturin build

# Build manylinux1 wheelhouse
sudo docker build . --tag polkasource/maturin
sudo docker run --rm -i -v $(pwd):/io polkasource/maturin build

#!/bin/bash
sudo ./cpupower frequency-set --governor performance
echo "Set CPU governor to performance, looking up for validation"
./cpupower frequency-info -o proc

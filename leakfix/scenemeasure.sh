#!/bin/bash
# Measure /GetSceneList, the one scene API endpoint that answers 200.
#
# This is the driver the six latent scene leaks needed. Two runs, because a
# single slope is not a result: consecutive runs must agree before the number
# is believed.
set -u
cd /work/fwcheck
for r in 1 2; do
    echo "run $r"
    sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode api \
        --endpoint /GetSceneList --plain "operation=get" \
        --warmup 200 --n 300 --every 100 2>&1 \
        | grep -E "statuses|requests|rss|slope" | sed 's/^/  /'
done
echo "control: the known-clean API endpoint, same session"
sudo timeout 600 python3 leakprobe.py --host 127.0.0.1 --mode api \
    --warmup 200 --n 300 --every 100 2>&1 \
    | grep -E "statuses|rss|slope" | sed 's/^/  /'
echo DONE-SCENEMEASURE

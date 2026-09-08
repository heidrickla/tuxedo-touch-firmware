#!/bin/bash
# Try to find an API endpoint that reaches the scene helper functions, so the
# six latent tree leaks become drivable and therefore fixable-and-verifiable.
#
# checkIfSceneExists / checkSceneNameExists / deleteExistngScene /
# editSceneDetails / discoveredTuxedos / getCameraRecording each receive a
# parsed tree from scene_getRootNodeOfObjects and never free it. They are not on
# the periodic path, so they are latent rather than urgent -- but a fix cannot be
# verified without a way to execute them.
#
# Only READ-shaped endpoints are tried. Nothing here creates, edits or deletes a
# scene: this runs against the emulator, but a scene-mutating probe would still
# be the wrong habit to build.
set -u
cd /work/fwcheck
for ep in /GetSceneList /getScenes /getEScenes /allscenes /GetSceneDetails \
          /getSceneList /SceneList /GetDiscoveredTuxedos /getDiscoverCameras; do
    out=$(sudo timeout 120 python3 leakprobe.py --host 127.0.0.1 --mode api \
            --endpoint "$ep" --plain "operation=get" --warmup 5 --n 5 --every 5 2>&1)
    st=$(echo "$out" | grep -oE "measured statuses: \{.*\}" | sed 's/measured statuses: //')
    printf "  %-24s %s\n" "$ep" "${st:-NO-OUTPUT}"
done
echo DONE-SCENEPROBE

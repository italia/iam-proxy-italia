#!/bin/bash
# Remove every image referenced by this compose file.
# The next ./run-docker-compose.sh then pulls registry images and builds
# the ones that exist only as a local Dockerfile.
#
# Bind-mounted data and the external iam-proxy-italia network are kept.
# Shared tags (mongo, nginx:alpine, certbot/certbot, ...) are removed too,
# because this compose uses them.

cd "$(dirname "$0")"

echo "Stopping compose services so their images can be removed."
echo "The external network iam-proxy-italia is kept."
docker compose -f docker-compose.yml --profile '*' down --remove-orphans

echo ""
echo "Removing images used by docker-compose.yml."
mapfile -t images < <(docker compose -f docker-compose.yml --profile '*' config --images | awk 'NF && !seen[$0]++')

if [ "${#images[@]}" -eq 0 ]; then
  echo "Compose listed no images."
  exit 0
fi

failed=0
for image in "${images[@]}"; do
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "Removing ${image}"
    if ! docker image rm "${image}"; then
      echo "Could not remove ${image}. Another container may still be using it."
      failed=1
    fi
  else
    echo "Not present locally: ${image}"
  fi
done

exit "${failed}"

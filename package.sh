#!/bin/bash
if [ $# -ne 1 ]; then
  echo "You need to specify a tag"
  exit 1
fi
git add .
git commit -m "packaging"
git push
git tag -d v${1}
git push origin :refs/tags/v${1}
git tag -a v${1} -m "${1} release"
git push --tags


#!/bin/bash

if [ $# -ne 2 ]; then
    echo "You need to specify a tag and message"
    exit 1
fi
git add .
git commit -m "${2}"
git push
git tag -d v${1}
git push origin :refs/tags/v${1}
git tag -a v${1} -m "${1} release"
git push --tags


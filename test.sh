#!/bin/bash
CMD=$0
if [ $1 -lt 1 ]; then
    exit 0
else
    for i in {1..10}; do
        echo "writing to /tmp/foo$i"
        node -e "console.log('NODE START');require('child_process').execSync('touch /tmp/bar');console.log('NODE END');"
    done
    echo "Running $CMD with $1"
    bash $CMD $(($1-1))
fi

#!/bin/bash
while true; do
  curl -s http://localhost:8080/ > /dev/null 2>&1
  sleep 300
done

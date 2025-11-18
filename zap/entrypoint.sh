#!/bin/bash
echo "Executing entrypoint"
echo "Copying /tmp-pre-boot into /tmp"
cp -fr /tmp-pre-boot/. /tmp/
java $JAVA_OPTS -javaagent:/app/opentelemetry-javaagent.jar -jar /app/zap.jar

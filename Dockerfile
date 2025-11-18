# syntax=docker/dockerfile:1
ARG BASE_FINAL_IMAGE=eclipse-temurin:17-jammy
ARG BASE_BUILD_IMAGE=maven:3.9.11-eclipse-temurin-17
ARG DEPS_IMAGE=alpine:3.20

######## Build ########
FROM ${BASE_BUILD_IMAGE} AS build
ARG PROJECT_KEY
ARG SONAR_HOST
ARG SONAR_LOGIN

WORKDIR /src
# this copy uses the .dockerignore to only copy src .m2 and pom.xml
COPY . /src/

# LOG_DIR is needed because the plugins are writing log files 
ENV LOG_DIR=/tmp/logs/
ENV LOG_LEVEL=INFO

# Maven deploy
RUN mvn -e -s .m2/settings.xml clean deploy sonar:sonar \
    -Dsonar.projectKey=${PROJECT_KEY} \
    -Dsonar.host.url=${SONAR_HOST} \
    -Dsonar.login=${SONAR_LOGIN}

######## Dependencies ########
FROM ${DEPS_IMAGE} as deps
WORKDIR /app/
# download OTLP javaagent as a dependency and we can copy it into the final image
RUN wget -O opentelemetry-javaagent.jar https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/latest/download/opentelemetry-javaagent.jar

######## Final Image  ########
FROM ${BASE_FINAL_IMAGE}
WORKDIR /app

# update packages and install
RUN echo "===> OS Update..." \
    && DEBIAN_FRONTEND=noninteractive apt-get update -q \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -yq ca-certificates \
    && DEBIAN_FRONTEND=noninteractive apt-get clean

# userid and groupid to run as
ARG UID=1000
ARG GID=1000

# create non-priv user and group and set homedir as /tmp
RUN groupadd -g "${GID}" non-priv \
  && useradd --create-home -d /tmp --no-log-init -u "${UID}" -g "${GID}" non-priv
# create tmp-pre-boot folder to allow copying into /tmp on bootup and fix permissions
# before changing user (but user must have been created already)
RUN mkdir /tmp-pre-boot || true && chown -R non-priv:non-priv /tmp-pre-boot
USER non-priv

COPY --chown=${UID}:${GID} --from=deps /app/opentelemetry-javaagent.jar /app/opentelemetry-javaagent.jar
COPY --chown=${UID}:${GID} --from=build /src/target/zap.jar /app/zap.jar
COPY --chown=${UID}:${GID} --from=build /src/entrypoint.sh /app/entrypoint.sh
ADD --chown=${UID}:${GID} auth0-auth.js /app/zap/auth0-auth.js

# LOG_DIR is needed because the plugins are writing log files for tomcat
ENV LOG_DIR=/tmp/logs/
ENV LOG_LEVEL=DEBUG

# move /tmp content into /tmp-pre-boot so entrypoint.sh can copy it back after mounting /tmp
RUN cp -R /tmp/. /tmp-pre-boot/

ENTRYPOINT ["./entrypoint.sh"]

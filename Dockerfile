# Stage 1
FROM docker.io/gradle:9.3.1-jdk25 AS temp_build
ARG SKIP_TESTS=false
WORKDIR /home/gradle/src
# Copy the project files
COPY build.gradle settings.gradle /home/gradle/src/
COPY src /home/gradle/src/src
COPY gradle /home/gradle/src/gradle
COPY config /home/gradle/src/config
# Build the project
RUN if [ "$SKIP_TESTS" = "true" ]; then \
    gradle build --no-daemon -x test; \
  else \
    gradle build --no-daemon; \
  fi

# Stage 2
FROM eclipse-temurin:25-jre-alpine
RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot

# ADOT Java Agent — activated via JAVA_TOOL_OPTIONS="-javaagent:/opt/aws-opentelemetry-agent.jar"
ARG ADOT_VERSION=2.11.2
ADD --chmod=444 \
    https://github.com/aws-observability/aws-otel-java-instrumentation/releases/download/v${ADOT_VERSION}/aws-opentelemetry-agent.jar \
    /opt/aws-opentelemetry-agent.jar

USER nonroot
WORKDIR /app
COPY --from=temp_build /home/gradle/src/build/libs/*.jar /app/wallet-ebw.jar
ENTRYPOINT ["java", "-jar", "/app/wallet-ebw.jar"]

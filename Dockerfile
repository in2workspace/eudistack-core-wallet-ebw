# ---------------------------------------------------------------------------
# Multi-stage build for the EBW (Enterprise Business Wallet) Core Backend
# ---------------------------------------------------------------------------

# --- Stage 1: build --------------------------------------------------------
FROM docker.io/gradle:9.3.1-jdk25 AS build
ARG SKIP_TESTS=false
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src
RUN if [ "$SKIP_TESTS" = "true" ]; then \
      gradle build --no-daemon -x test -x integrationTest; \
    else \
      gradle build --no-daemon; \
    fi

# --- Stage 2: runtime ------------------------------------------------------
FROM eclipse-temurin:25-jre-alpine
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
USER nonroot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/ebw.jar
ENTRYPOINT ["java", "-jar", "/app/ebw.jar"]

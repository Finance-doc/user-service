FROM openjdk:17-jdk-slim AS builder

WORKDIR /app
COPY . .

RUN chmod +x ./gradlew

RUN ./gradlew bootJar --no-daemon

RUN ls -l /app/build/libs

# 1. Java 17 기반 이미지 사용
FROM openjdk:17-jdk-slim

WORKDIR /app

COPY --from=builder /app/build/libs/*.jar app.jar

# 3. 포트 오픈 (yml에서 설정한 8080)
EXPOSE 8080

# 4. 실행 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]
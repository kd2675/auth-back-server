# auth-back-server

인증 및 사용자 관리 서비스입니다. JWT 액세스/리프레시 토큰을 발급하고, 사용자 조회/관리 API를 제공합니다.

## 역할
- 로그인/리프레시/로그아웃/토큰 검증
- 사용자 CRUD 및 조회

## 포트
- local: 9000
- dev: 20180
- prod: 10180
- test: 30180

## 실행
```bash
./gradlew auth-back-server:bootRun
```

프로파일 지정:
```bash
./gradlew auth-back-server:bootRun --args='--spring.profiles.active=local'
./gradlew auth-back-server:bootRun --args='--spring.profiles.active=dev'
./gradlew auth-back-server:bootRun --args='--spring.profiles.active=prod'
./gradlew auth-back-server:bootRun --args='--spring.profiles.active=test'
```

## 주요 노트
- JWT 발급/갱신/검증을 담당합니다.
- 기본 활성 프로파일은 `local`입니다.
- 유레카에 등록되는 클라이언트입니다.
- 토큰 시크릿은 `cloud-back-server`와 동일해야 합니다.

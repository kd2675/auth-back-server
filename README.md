# auth-back-server

인증 및 사용자 관리 서버입니다. 로컬 로그인, OAuth2 로그인, JWT 발급/갱신/검증, 사용자 CRUD를 담당합니다.

## 역할
- `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/validate`
- `GET/POST/PUT/DELETE /api/users/**`
- Naver/Kakao OAuth2 client 구성과 소셜 로그인 세션 저장
- Eureka 등록 클라이언트

## 포트
| Profile | Port |
|---|---:|
| `local` | 9000 |
| `local-direct` | 9000 |
| `dev` | 20180 |
| `prod` | 10180 |
| `test` | 30180 |

## 실행
```bash
./gradlew :auth-back-server:bootRun
./gradlew :auth-back-server:bootRun --args='--spring.profiles.active=local'
./gradlew :auth-back-server:bootRun --args='--spring.profiles.active=local-direct'
./gradlew :auth-back-server:bootRun --args='--spring.profiles.active=dev'
./gradlew :auth-back-server:bootRun --args='--spring.profiles.active=prod'
./gradlew :auth-back-server:bootRun --args='--spring.profiles.active=test'
```

## 빌드 / 테스트
```bash
./gradlew :auth-back-server:compileJava
./gradlew :auth-back-server:test
```

## OAuth / Client Notes
- 소셜 provider: `naver`, `kakao`
- 프론트 client: `muse-front-service`, `zeroq-front-service`, `zeroq-front-admin`, `semo-front-service`, `stock-front-service`
- redirect URI와 post logout URI는 `application.yml`의 `app.oauth2.front-clients` 기준으로 관리합니다.
- Spring Authorization Server JDBC 모델은 등록 client와 소셜 세션 저장에만 사용하며, 별도 authorization-server protocol endpoint는 노출하지 않습니다.
- Stock OAuth 성공은 URL에 access token을 붙이지 않고 `/auth/callback`에서 HttpOnly refresh cookie로 교환합니다.

## 구성 포인트
- DB: profile별 MySQL, 테스트는 H2
- JWT secret: `AUTH_JWT_SECRET`
- OAuth client secret: `NAVER_CLIENT_SECRET`, `KAKAO_CLIENT_SECRET`
- Gateway의 `CLOUD_JWT_SECRET`과 `AUTH_JWT_SECRET` 정합성이 맞아야 합니다.
- access token은 issuer, 서비스별 audience, `api` scope를 포함합니다.
- refresh token은 5시간 절대 만료, 요청별 rotation, token-family 재사용 탐지를 적용합니다. 기존 DB에는 서버 기동 전에 `db/ddl/auth_refresh_token_rotation_alter.sql`을 1회 적용합니다.
- 운영 환경은 `AUTH_ISSUER`, `AUTH_CORS_ALLOWED_ORIGINS`, 각 `*_FRONT_BASE_URL`을 HTTPS 공개 주소로 반드시 지정합니다.

## Local Direct / Gateway 전환

- `local-direct`는 `local` DB/OAuth 설정을 재사용하면서 Eureka 등록/탐색을 끕니다.
- Gateway/Eureka 경유로 되돌리려면 기존 `local` profile을 사용합니다.
- 전환 예시는 `.env.example`에 주석으로 남겨둡니다.

## 주요 패키지
- `config`, `config/handler`
- `controller`
- `database/pub`
- `datasource`
- `service`, `service/oauth2`

## 참고
- 기본 활성 프로파일은 로컬 direct 개발용 `local-direct`입니다.
- 토큰 만료 시간, OAuth redirect, manager signup secret은 `src/main/resources/application.yml`에서 관리합니다.

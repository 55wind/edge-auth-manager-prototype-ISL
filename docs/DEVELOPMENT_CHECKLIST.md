# 주요 개발 내용 체크리스트

## 범례

- [x] 구현 완료
- 각 항목에 **구현 위치**(파일:함수/라인)와 **대시보드 확인 방법** 기재

---

## 1. 요구사항 정의 및 정책 설계

### 1.1 디바이스 ID 네임스페이스/상태전이와 등록·승인 정책

- [x] **`{domain}/{site}/{group}/{deviceId}` 네임스페이스 규칙**
  - 구현: `services/manager/manager/models.py:7-26` — `_NS_SEGMENT_RE` 정규식 + `validate_ns_segment()` 검증
  - 네임스페이스 생성: `services/manager/manager/main.py:326` — `f"{body.domain}/{body.site}/{body.group}/{body.device_id}"`
  - 대시보드: Devices 페이지에서 Namespace 컬럼 확인, Test Scenarios에서 네임스페이스 검증 테스트

- [x] **상태전이: PENDING → APPROVED → REVOKED**
  - 구현: `services/manager/manager/main.py` — `device_register()` (PENDING), `device_approve()` (APPROVED), `device_revoke()` (REVOKED)
  - 대시보드: Devices 페이지에서 상태별 색상 코딩 (노랑/초록/빨강)

- [x] **양도(Transfer) 절차**
  - 구현: `services/manager/manager/main.py:408` — `/device/transfer` 엔드포인트
  - 모델: `services/manager/manager/models.py` — `DeviceTransferIn` (new_site, new_group, reason)
  - 대시보드: Devices 페이지 > Transfer 버튼 > 이관 폼

- [x] **폐기(Decommission) 절차**
  - 구현: `services/manager/manager/main.py:391` — `/device/decommission` 엔드포인트
  - 대시보드: Devices 페이지 > Decommission 버튼

- [x] **중복 등록 방지 (hw_fingerprint)**
  - 구현: `services/manager/manager/main.py:334-348` — 핑거프린트 불일치 시 409 Conflict
  - 대시보드: Security 페이지에서 DUPLICATE_FINGERPRINT 인시던트 확인

---

### 1.2 내부/외부 통신 구간 구분 및 QoS 기준

- [x] **온디바이스↔게이트웨이(내부) / 게이트웨이↔관리자(외부) 구분**
  - 구현: `docker-compose.yml:118-128` — `internal` 네트워크 (bridge, `internal: true`) + `external` 네트워크
  - Agent, RabbitMQ → internal 네트워크만
  - Dashboard → external 네트워크만
  - Manager → internal + external (브릿지)

- [x] **재시도/백오프 (QoS)**
  - HTTP 재시도: `services/agent/agent/client.py:28,35` — `@retry(stop=stop_after_attempt(5), wait=wait_exponential_jitter(initial=0.5, max=8))`
  - AMQP 재연결: `services/agent/agent/amqp_pub.py:108-118` — 최대 30회, 0.5s~20s 지수 백오프
  - Discovery 재시도: `services/agent/agent/discovery.py:14` — 5회 시도, 1s~15s 백오프

---

### 1.3 상호인증(mTLS) 정책

- [x] **Manager mTLS 강제 (ssl.CERT_REQUIRED)**
  - 구현: `services/manager/manager/main.py:809-820` — uvicorn `ssl_cert_reqs=ssl.CERT_REQUIRED`
  - 서버 인증서: `certs/manager/server.crt`, `certs/manager/server.key`

- [x] **RabbitMQ mTLS 강제 (verify_peer)**
  - 구현: `ops/rabbitmq/rabbitmq.conf:10-11` — `ssl_options.verify = verify_peer`, `fail_if_no_peer_cert = true`

- [x] **Agent mTLS 클라이언트**
  - 구현: `services/agent/agent/client.py:15-26` — `_mtls_client()` (httpx.Client with verify + cert)
  - AMQP mTLS: `services/agent/agent/amqp_pub.py:31-37` — `_ssl_context()` with `load_cert_chain()`

- [x] **스코프/TTL 정의**
  - JWT TTL: `services/manager/manager/main.py:49` — `JWT_TTL_SECONDS` (기본 900초/15분)
  - JWT 스코프: `services/manager/manager/security.py:13-25` — sub(네임스페이스), roles, iss, aud, exp

- [x] **만료 대응: 토큰 자동 갱신 (80% TTL)**
  - 구현: `services/agent/agent/run.py:94-117` — TTL의 80% 지점에서 자동 갱신
  - 대시보드: Authentication 페이지에서 TOKEN_ISSUED 이벤트 연속 확인

- [x] **폐기 대응: REVOKED 디바이스 즉시 차단**
  - 구현: `services/agent/agent/run.py:70-74,104-108` — REVOKED 감지 시 에이전트 중지
  - 서버: `services/manager/manager/main.py:444-465` — REVOKED 디바이스 토큰 발급 거부 (403)

- [x] **탈취 대응: 토큰 블록리스트**
  - 구현: `services/manager/manager/main.py:65` — `_token_blocklist` (네임스페이스별 JTI 집합)
  - 엔드포인트: `/admin/revoke-tokens` — 특정 네임스페이스의 토큰 일괄 차단
  - 대시보드: Authentication 페이지 > JWT Security Status > Blocked Tokens

---

### 1.4 인가(RBAC) 및 무결성/전송 보안

- [x] **Role/리소스 권한 매트릭스**
  - 구현: `services/manager/manager/main.py:67-80` — `RBAC_MATRIX` dict
  - admin: 전체 경로 접근
  - agent: `/device/register`, `/auth/token`, `/auth/validate`, `/cert/status`만 허용
  - 엔드포인트: `/admin/rbac-matrix` — 매트릭스 조회
  - 대시보드: Authentication 페이지 > RBAC Permission Matrix (확장 가능)

- [x] **HMAC/서명 강제**
  - AMQP 메시지 서명: `services/agent/agent/amqp_pub.py:39-43` — `_sign_message()` (HMAC-SHA256)
  - 서버 검증: `services/manager/manager/main.py:318-320` — `compute_hmac()` + `/admin/verify-hmac` 엔드포인트
  - 대시보드: Authentication 페이지 > JWT Security Status > HMAC Algorithm

---

### 1.5 비밀값·암호화키 수명주기 관리

- [x] **루트/중간 CA 연동 (2계층 PKI)**
  - 구현: `ops/gen_certs.py:56-80` — `_mk_ca()` (Root CA, 10년, path_length=1)
  - 구현: `ops/gen_certs.py:83-107` — `_mk_intermediate()` (Intermediate CA, 5년, path_length=0)
  - 모든 리프 인증서는 Intermediate CA가 서명
  - 체인 파일: `certs/ca-chain.crt` (intermediate + root)

- [x] **CRL (Certificate Revocation List)**
  - 생성: `ops/gen_certs.py:145-154` — `_mk_empty_crl()` (Intermediate CA 서명)
  - 런타임 조회: `services/manager/manager/main.py:537-555` — `/cert/crl` 엔드포인트
  - 대시보드: Devices 페이지 > Certificate Revocation List 섹션

- [x] **무중단 JWT 시크릿 로테이션**
  - 구현: `services/manager/manager/main.py:56-59,560-572` — `/admin/rotate-jwt-secret`
  - Grace period: `_JWT_ROTATION_GRACE_SECONDS` (기본 120초) 동안 이전+현재 시크릿 모두 유효
  - 대시보드: Authentication 페이지 > JWT Security Status > Last Rotation

---

### 1.6 Agent / Gateway / Manager 3계층 모델

- [x] **Agent (에이전트 계층)**
  - 구현: `services/agent/` — 디바이스에서 실행되는 경량 보안 모듈
  - 역할: 등록, 토큰 갱신, 메타데이터 발행

- [x] **Gateway (게이트웨이 계층 — RabbitMQ)**
  - 구현: `docker-compose.yml:2-21` — RabbitMQ 3.13 (TLS AMQP)
  - 역할: 에이전트↔매니저 간 메시지 중계, TLS 종단

- [x] **Manager (제어 계층)**
  - 구현: `services/manager/` — FastAPI 기반 인증/인가/인증서 관리 서비스
  - 역할: 디바이스 등록/승인, JWT 발급, 인증서 추적, 메트릭스

- [x] **메시지버스 네임스페이스 및 바인딩 정책**
  - 큐: `agent.metadata` (durable)
  - 권한 제한: `ops/rabbitmq/definitions.json:12-19` — `^agent\.metadata$` (정규식 제한)
  - 대시보드: Test Scenarios에서 RabbitMQ 권한 제한 테스트

---

### 1.7 인증·데이터 흐름 시퀀스

- [x] **정상 흐름: 부트 → 등록 → 승인 → 인증 → 권한부여 → 데이터교환**
  - 구현: `services/agent/agent/run.py:33-137` — `agent_loop()` 전체 흐름
    - 부트: 인증서 만료 확인 (line 41)
    - 탐색: `discover_manager()` (line 45)
    - 등록: `register()` (line 58)
    - 승인 대기 + 인증: `get_token()` 폴링 (line 99)
    - 데이터교환: `pub.publish(msg)` (line 136)

- [x] **예외 흐름: 중복 등록**
  - 구현: `services/agent/agent/run.py:59-64` — 409 Conflict 시 에이전트 중지

- [x] **예외 흐름: 폐기된 디바이스**
  - 구현: `services/agent/agent/run.py:70-74,104-108` — REVOKED 감지 시 즉시 중지

- [x] **예외 흐름: 연결 단절/재연결**
  - 구현: `services/agent/agent/amqp_pub.py:67-118` — 예외 → 로컬 버퍼 → 재연결 → 플러시

---

### 1.8 운영/관찰성 구조

- [x] **구조화 로그 (Structured Logging)**
  - 구현: `services/manager/manager/main.py:109-157` — `MetricsMiddleware`
  - 필드: method, path, status_code, latency_ms, client_cn, correlation_id, timestamp

- [x] **Correlation ID (X-Request-Id)**
  - 구현: `services/manager/manager/main.py:116` — 요청마다 UUID 할당/전파
  - 대시보드: Logs 페이지 > Correlation ID 컬럼

- [x] **Client CN 추출**
  - 구현: `services/manager/manager/main.py:89-106` — `_extract_client_cn()` (TLS peer cert에서 CN 추출)
  - 대시보드: Logs 페이지 > Client CN 컬럼

- [x] **메트릭스 엔드포인트**
  - `/metrics/overview`, `/metrics/auth`, `/metrics/auth/hourly`, `/metrics/auth/devices`
  - `/metrics/requests/hourly`, `/metrics/devices/stale`, `/metrics/system`
  - `/metrics/security`, `/metrics/security/counts`, `/metrics/security/by-type`

---

## 2. 핵심 소프트웨어 프로토타입 개발

### 2.1 경량 에이전트 보안 모듈

- [x] **등록 기능**
  - 구현: `services/agent/agent/client.py:28` — `register()` (POST /device/register)
  - hw_fingerprint 생성: `services/agent/agent/run.py:25-28` — SHA-256(platform 정보)

- [x] **탐색 기능 (Manager 프로브)**
  - 구현: `services/agent/agent/discovery.py:14` — `discover_manager()` (/healthz 프로브)

- [x] **메타데이터 전송**
  - 구현: `services/agent/agent/amqp_pub.py:67-85` — `SecurePublisher.publish()`
  - 메시지 형식: namespace, device_id, sensor_type, ts, token_hint, metrics

- [x] **비동기 이벤트 루프**
  - 구현: `services/agent/agent/run.py:33,146` — `async def agent_loop()` + `asyncio.run()`

- [x] **재시도/백오프 (tenacity)**
  - HTTP: `services/agent/agent/client.py:28,35` — 5회, 0.5s~8s
  - AMQP: `services/agent/agent/amqp_pub.py:108-118` — 30회, 0.5s~20s

- [x] **mTLS 핸드셰이크·세션 유지**
  - 구현: `services/agent/agent/client.py:15-26` — `_mtls_client()` (httpx.Client)

- [x] **인증서 만료 사전 경고**
  - 구현: `services/agent/agent/cert_check.py:17` — `check_cert_expiry()` (7일 전 경고)

---

### 2.2 인증 모듈 API

- [x] **`/cert/issue` — 인증서 발급**
  - 구현: `services/manager/manager/main.py:499`

- [x] **`/cert/renew` — 인증서 갱신**
  - 구현: `services/manager/manager/main.py:506`

- [x] **`/cert/revoke` — 인증서 폐기**
  - 구현: `services/manager/manager/main.py:524`

- [x] **`/cert/status` — 인증서 상태 조회**
  - 구현: `services/manager/manager/main.py:529`

- [x] **`/cert/crl` — 인증서 폐기 목록**
  - 구현: `services/manager/manager/main.py:537`

- [x] **`/auth/token` — JWT 토큰 발급**
  - 구현: `services/manager/manager/main.py:444`
  - APPROVED 디바이스만 발급, JTI(uuid4) 포함

- [x] **`/auth/validate` — 토큰 검증**
  - 구현: `services/manager/manager/main.py:467`
  - 블록리스트 확인, 로테이션 grace period 지원

- [x] **승인 검증 (Admin Token)**
  - 구현: `services/manager/manager/main.py` — `require_admin()` (X-Admin-Token 헤더)
  - 대시보드: 모든 관리 작업에 자동 적용 (utils.py에서 헤더 자동 추가)

---

### 2.3 메시지버스 보안채널 모듈

- [x] **TLS 설정 (AMQP over TLS)**
  - 서버: `ops/rabbitmq/rabbitmq.conf:2-3` — `listeners.tcp = none`, `listeners.ssl.default = 5671`
  - 클라이언트: `services/agent/agent/amqp_pub.py:31-37` — `_ssl_context()` (CA 검증 + 클라이언트 인증서)

- [x] **큐 바인딩**
  - 구현: `services/agent/agent/amqp_pub.py:52-53` — `queue_declare("agent.metadata", durable=True)`

- [x] **재접속/미전송 버퍼**
  - 재접속: `services/agent/agent/amqp_pub.py:104-118` — `_reconnect_with_backoff()` (30회, 지수 백오프)
  - 버퍼: `services/agent/agent/buffer.py` — `JsonlBuffer` (`unsent.jsonl` 파일)
  - 플러시: `services/agent/agent/amqp_pub.py:87-102` — `flush()` (최대 200건)

- [x] **키 교체 중 서비스 지속**
  - 구현: `services/agent/agent/amqp_pub.py:67-85` — 예외 발생 시 로컬 버퍼 → 재연결 → 플러시
  - 검증: `ops/rotate_demo.md` 절차 참조

---

### 2.4 컨테이너 이미지, 초기 설정·설치 스크립트

- [x] **컨테이너 이미지 (Dockerfile)**
  - Manager: `services/manager/Dockerfile` — python:3.11-slim, USER manager(1001)
  - Agent: `services/agent/Dockerfile` — python:3.11-slim, USER agent(1002)
  - Dashboard: `services/dashboard/Dockerfile` — python:3.11-slim, USER dashboard(1003)

- [x] **TLS 강제**
  - Manager: HTTPS only (포트 8443), HTTP 리스너 없음
  - RabbitMQ: `listeners.tcp = none` (평문 TCP 비활성화)

- [x] **기본계정 제거**
  - 구현: `ops/rabbitmq/definitions.json` — `isl` 사용자만 정의, guest 미포함
  - 설정: `ops/rabbitmq/rabbitmq.conf:19` — `loopback_users.guest = false`

- [x] **최소권한 Role**
  - 구현: `ops/rabbitmq/definitions.json:12-19` — `^agent\.metadata$` 정규식으로 큐 접근 제한

- [x] **인증서 생성 스크립트**
  - 구현: `ops/gen_certs.py` — Root CA → Intermediate CA → 리프 인증서 + CRL 자동 생성

- [x] **Docker Compose 오케스트레이션**
  - 구현: `docker-compose.yml` — 5개 서비스 (rabbitmq, manager, dashboard, agent-001, agent-002)
  - 헬스체크, 의존성 순서, 볼륨 마운트, 네트워크 분리 포함

---

## 3. 개발 환경

- [x] **Linux**: CentOS 7.8 이상, Ubuntu 20.04 LTS 이상
- [x] **Docker**: 28.4 이상
- [x] **Kubernetes**: 1.30 이상
- [x] **IDE**: Visual Studio Code, PyCharm

---

## 4. 결과물 (용역 결과물)

### 4.1 소프트웨어 패키지

- [x] **경량 Agent 모듈 실행 패키지**
  - 위치: `services/agent/`
  - 포함: 등록(`client.py`), 탐색(`discovery.py`), 메타데이터 전송(`amqp_pub.py`), mTLS 핸드셰이크(`client.py:15-26`)
  - 실행: `python -m agent.run --device-id <id> --site <site> --group <group>`

- [x] **인증 모듈 API 및 Manager 서비스 패키지**
  - 위치: `services/manager/`
  - 포함: FastAPI 앱(`main.py`), DB 모델(`db.py`), Pydantic 스키마(`models.py`), JWT 보안(`security.py`)
  - 엔드포인트: `/device/*`, `/auth/*`, `/cert/*`, `/admin/*`, `/metrics/*`

- [x] **메시지버스 보안채널 플러그인/라이브러리**
  - 위치: `services/agent/agent/amqp_pub.py` + `services/agent/agent/buffer.py`
  - 포함: TLS AMQP 퍼블리셔, HMAC 서명, 로컬 JSONL 버퍼, 지수 백오프 재연결

- [x] **배포/운영 스크립트**
  - 컨테이너 이미지: `services/*/Dockerfile` (3개)
  - 오케스트레이션: `docker-compose.yml`
  - 인증서 생성: `ops/gen_certs.py`
  - RabbitMQ 초기 설정: `ops/rabbitmq/definitions.json`, `ops/rabbitmq/rabbitmq.conf`

- [x] **샘플 클라이언트/데모 스크립트**
  - RabbitMQ 소비자 데모: `services/agent/agent/consume_demo.py`
  - 키 로테이션 데모 절차: `ops/rotate_demo.md`
  - 대시보드 테스트 시나리오: `services/dashboard/dashboard/pages/8_Test_Scenarios.py`

---

## 요약

| 구분 | 항목 수 | 구현 완료 | 완료율 |
|------|---------|----------|--------|
| 요구사항 정의 및 정책 설계 | 28 | 28 | 100% |
| 핵심 소프트웨어 프로토타입 | 24 | 24 | 100% |
| 개발 환경 | 4 | 4 | 100% |
| 용역 결과물 | 5 | 5 | 100% |
| **전체** | **61** | **61** | **100%** |

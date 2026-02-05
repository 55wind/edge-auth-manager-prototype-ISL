# 발표용 스크린샷 촬영 가이드

## 사전 준비

```bash
# 서비스 실행 확인
docker compose up -d

# 접속 URL
# - 대시보드: http://localhost:8501
# - RabbitMQ: http://localhost:15672 (ID: isl / PW: wjdqhqhghdusrntlf1!)
```

---

## 스크린샷 목록 및 촬영 위치

### 1. 요구사항 정의 및 정책 설계

#### 1-1. 디바이스 ID 네임스페이스/상태전이와 등록·승인 정책

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `01_namespace_device_list.png` | Devices 페이지 | 디바이스 목록 테이블 (Namespace 컬럼에 `default/factory-A/sensors/agent-001` 형식 보이게) |
| `02_status_pending.png` | Devices 페이지 | 상태 필터를 PENDING으로 설정한 화면 (노란색 하이라이트) |
| `03_status_approved.png` | Devices 페이지 | 상태 필터를 APPROVED로 설정한 화면 (녹색 하이라이트) |
| `04_status_revoked.png` | Devices 페이지 | 상태 필터를 REVOKED로 설정한 화면 (빨간색 하이라이트) |
| `05_admin_actions.png` | Devices 페이지 | Admin Actions 버튼들 (Approve, Revoke, Issue Cert, Renew Cert, Decommission, Transfer) |
| `06_transfer_form.png` | Devices 페이지 | Transfer 버튼 클릭 후 나오는 이관 폼 |

**설명 포인트:**
- 네임스페이스 형식: `{domain}/{site}/{group}/{deviceId}`
- 상태전이: PENDING → APPROVED → REVOKED
- 양도/폐기 버튼으로 디바이스 생명주기 관리

---

#### 1-2. 내부/외부 통신 구간 구분 및 QoS

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `07_network_overview.png` | Overview 페이지 | Security Posture 섹션 (mTLS Enforced 표시) |
| `08_test_mtls.png` | Test Scenarios 페이지 | Async/mTLS/Session 카테고리 테스트 결과 |
| `09_rabbitmq_connections.png` | RabbitMQ (localhost:15672) | Connections 탭 - TLS 연결 상태 (ssl=true) |

**설명 포인트:**
- 내부 네트워크: Agent ↔ RabbitMQ (internal, 격리됨)
- 외부 네트워크: Dashboard ↔ Manager
- 재시도/백오프: tenacity 라이브러리 (5회 시도, 0.5s~8s 지수 백오프)

---

#### 1-3. 상호인증(mTLS) 정책

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `10_jwt_security_status.png` | Authentication 페이지 | JWT Security Status 섹션 (Algorithm, TTL, HMAC, Blocked Tokens) |
| `11_auth_summary.png` | Authentication 페이지 | Authentication Summary 카드들 (Total Attempts, Successes, Failures, Success Rate) |
| `12_token_events.png` | Authentication 페이지 | Events by Type 섹션 (TOKEN_ISSUED, TOKEN_DENIED 등) |

**설명 포인트:**
- JWT TTL: 900초 (15분)
- 자동 갱신: TTL의 80% 시점
- 토큰 블록리스트로 탈취 대응

---

#### 1-4. 인가(RBAC) 및 무결성/전송 보안

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `13_rbac_matrix.png` | Authentication 페이지 | RBAC Permission Matrix 확장하여 캡처 (admin/agent 역할별 경로) |
| `14_hmac_algorithm.png` | Authentication 페이지 | JWT Security Status에서 HMAC Algorithm 부분 |
| `15_test_rbac.png` | Test Scenarios 페이지 | Auth Module APIs 카테고리에서 RBAC 테스트 결과 |

**설명 포인트:**
- admin: 전체 경로 접근
- agent: 제한된 경로만 (/device/register, /auth/token 등)
- HMAC-SHA256으로 메시지 무결성 보장

---

#### 1-5. 비밀값·암호화키 수명주기 관리

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `16_crl_section.png` | Devices 페이지 | Certificate Revocation List (CRL) 섹션 |
| `17_cert_status.png` | Devices 페이지 | Certificate Status 섹션 (Status, Expires) |
| `18_last_rotation.png` | Authentication 페이지 | JWT Security Status > Last Rotation 부분 |
| `19_security_config.png` | Test Scenarios 페이지 > Security Config 탭 | CRL Revoked Certs, JWT Configuration 표시 |

**설명 포인트:**
- 2계층 PKI: Root CA (10년) → Intermediate CA (5년) → 리프 인증서
- CRL 엔드포인트로 폐기된 인증서 조회
- JWT 시크릿 무중단 로테이션 (120초 grace period)

---

#### 1-6. Agent / Gateway / Manager 3계층 모델

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `20_overview_metrics.png` | Overview 페이지 | Key Metrics 카드들 (Total Devices, Approved, API Requests, Auth Success Rate) |
| `21_rabbitmq_queues.png` | RabbitMQ (localhost:15672) | Queues 탭 - agent.metadata 큐 |
| `22_rabbitmq_overview.png` | RabbitMQ (localhost:15672) | Overview 탭 - 전체 상태 |
| `23_test_messagebus.png` | Test Scenarios 페이지 | Message Bus 카테고리 테스트 결과 |

**설명 포인트:**
- Agent: 디바이스에서 실행, 등록/토큰갱신/메타데이터 발행
- Gateway (RabbitMQ): TLS AMQP 메시지 중계
- Manager: 인증/인가/인증서 관리 API

---

#### 1-7. 인증·데이터 흐름 시퀀스

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `24_test_agent_security.png` | Test Scenarios 페이지 | Agent Security Module 카테고리 전체 결과 |
| `25_auth_events_timeline.png` | Authentication 페이지 | Auth Events Over Time 차트 |
| `26_security_incidents.png` | Security 페이지 | 인시던트 목록 (AUTH_FAILURE_BURST, REVOKED_ACCESS_ATTEMPT 등) |

**설명 포인트:**
- 정상 흐름: 부트 → 등록 → 승인 → 인증 → 데이터교환
- 예외 흐름: 중복등록(409), 폐기 디바이스(403), 연결 단절(버퍼+재연결)

---

#### 1-8. 운영/관찰성 구조

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `27_logs_page.png` | Logs 페이지 | 로그 테이블 (Timestamp, Method, Path, Status, Latency, Client CN, Correlation ID) |
| `28_logs_filter.png` | Logs 페이지 | 필터 옵션들 (Time range, Limit, Status filter) |
| `29_system_health.png` | Overview 페이지 | System Health 섹션 (Uptime, Avg Latency, Status) |

**설명 포인트:**
- 구조화 로그: method, path, status, latency, client_cn, correlation_id
- X-Request-Id로 분산 추적
- 메트릭스 엔드포인트: /metrics/*

---

### 2. 핵심 소프트웨어 프로토타입 개발

#### 2-1. 경량 에이전트 보안 모듈

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `30_device_registration.png` | Devices 페이지 | 등록된 디바이스 목록 (agent-001, agent-002) |
| `31_device_lastseen.png` | Devices 페이지 | Last Seen 컬럼 (최근 시간 표시 = 메타데이터 전송 중) |
| `32_test_registration.png` | Test Scenarios 페이지 | Agent Security Module > Register device 테스트 결과 |

**설명 포인트:**
- 비동기 이벤트 루프 (asyncio)
- 재시도/백오프 (tenacity)
- mTLS 클라이언트 세션 유지

---

#### 2-2. 인증 모듈 API

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `33_cert_actions.png` | Devices 페이지 | Issue Cert, Renew Cert 버튼들 |
| `34_cert_issued.png` | Devices 페이지 | Certificate Status = ISSUED + Expires 날짜 |
| `35_test_auth_apis.png` | Test Scenarios 페이지 | Auth Module APIs 카테고리 전체 결과 |
| `36_auth_failure_analysis.png` | Authentication 페이지 | Failure Analysis 섹션 |

**설명 포인트:**
- /cert: issue, renew, revoke, status, crl
- /auth: token (JWT 발급), validate (검증)
- APPROVED 디바이스만 토큰 발급

---

#### 2-3. 메시지버스 보안채널 모듈

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `37_rabbitmq_tls.png` | RabbitMQ (localhost:15672) | Connections에서 Protocol = AMQP 0-9-1 (TLS) |
| `38_queue_metadata.png` | RabbitMQ (localhost:15672) | Queues > agent.metadata 큐 상세 (Messages, Consumers) |
| `39_test_rmq_health.png` | Test Scenarios 페이지 | Message Bus > RabbitMQ health 테스트 결과 |
| `40_test_rmq_permissions.png` | Test Scenarios 페이지 | Message Bus > RabbitMQ permissions 테스트 결과 |

**설명 포인트:**
- TLS-only AMQP (TCP 비활성화)
- 재접속 + 로컬 버퍼 (unsent.jsonl)
- 키 교체 중에도 서비스 지속

---

#### 2-4. 컨테이너 이미지, 초기 설정·설치 스크립트

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `41_docker_ps.png` | 터미널 | `docker compose ps` 결과 (5개 서비스 Running) |
| `42_home_page.png` | Dashboard 메인 (localhost:8501) | Home 페이지 전체 (Quick Navigation, Quick Status) |
| `43_checklist_dashboard.png` | Checklist 페이지 | Dashboard-Verifiable Items 섹션 |
| `44_checklist_code.png` | Checklist 페이지 | Code-Verifiable Items 섹션 (하나 확장하여 코드 스니펫 보이게) |

**설명 포인트:**
- Non-root 컨테이너 (manager:1001, agent:1002, dashboard:1003)
- TLS 강제, guest 계정 제거
- 최소권한 Role (RabbitMQ 정규식 제한)

---

### 3. 테스트 시스템 전체 화면

| 파일명 | 촬영 위치 | 캡처 내용 |
|--------|----------|-----------|
| `45_test_current_cycle.png` | Test Scenarios > Current Cycle 탭 | 테스트 실행 중 결과 테이블 (Pass/Fail 색상) |
| `46_test_historical.png` | Test Scenarios > Historical Stats 탭 | 성공률 추세 차트 |
| `47_test_category.png` | Test Scenarios > Category Breakdown 탭 | 카테고리별 성공률 바 차트 |
| `48_test_log.png` | Test Scenarios > Test Log 탭 | 테스트 로그 필터링 |

---

## 촬영 순서 권장

1. **서비스 시작**: `docker compose up -d`
2. **대시보드 접속**: http://localhost:8501
3. **Test Scenarios 실행**: Start Continuous Testing 클릭 → 1~2 사이클 완료 대기
4. **각 페이지별 순서대로 촬영**:
   - Home → Overview → Devices → Authentication → Security → Logs → Checklist → Test Scenarios
5. **RabbitMQ 접속**: http://localhost:15672 (isl / wjdqhqhghdusrntlf1!)
6. **RabbitMQ 스크린샷**: Overview → Connections → Queues
7. **터미널**: `docker compose ps` 캡처

---

## PPT 슬라이드 구성 제안

| 슬라이드 | 제목 | 스크린샷 | 설명 |
|----------|------|----------|------|
| 1 | 표지 | - | Edge Auth Manager 프로토타입 |
| 2 | 시스템 개요 | 42, 20 | 대시보드 메인 + Overview |
| 3 | 디바이스 네임스페이스 | 01, 05 | 네임스페이스 형식 + Admin Actions |
| 4 | 상태전이 | 02, 03, 04 | PENDING → APPROVED → REVOKED |
| 5 | 양도/폐기 | 05, 06 | Decommission, Transfer 버튼 |
| 6 | 네트워크 분리 | 07, 09 | Security Posture + RabbitMQ TLS |
| 7 | mTLS 정책 | 10, 08 | JWT Security + mTLS 테스트 |
| 8 | RBAC | 13, 15 | RBAC Matrix + 테스트 결과 |
| 9 | 인증서 관리 | 16, 17, 19 | CRL + Cert Status + Security Config |
| 10 | 3계층 아키텍처 | 21, 22, 23 | RabbitMQ + Message Bus 테스트 |
| 11 | 인증 흐름 | 24, 25 | Agent Security 테스트 + Auth Events |
| 12 | 관찰성 | 27, 29 | Logs + System Health |
| 13 | 에이전트 모듈 | 30, 32 | 디바이스 목록 + 등록 테스트 |
| 14 | 인증 API | 33, 35 | Cert Actions + Auth API 테스트 |
| 15 | 메시지버스 | 37, 38, 39 | RabbitMQ TLS + Queue + 테스트 |
| 16 | 컨테이너 | 41, 43 | docker ps + Checklist |
| 17 | 테스트 시스템 | 45, 46, 47 | Current Cycle + Historical + Category |
| 18 | 요약 | - | 61개 항목 100% 구현 완료 |

---

## 스크린샷 파일 저장 위치

```
docs/screenshots/
├── 01_namespace_device_list.png
├── 02_status_pending.png
├── ...
└── 48_test_log.png
```

총 48개 스크린샷 촬영 예정

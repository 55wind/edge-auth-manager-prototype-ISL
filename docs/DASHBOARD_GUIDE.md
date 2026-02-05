# Edge Auth Manager Dashboard 설명서

## 목차

1. [개요](#1-개요)
2. [접속 방법](#2-접속-방법)
3. [페이지별 설명](#3-페이지별-설명)
   - [Home (메인)](#31-home-메인)
   - [Overview (시스템 개요)](#32-overview-시스템-개요)
   - [Devices (장치 관리)](#33-devices-장치-관리)
   - [Authentication (인증 지표)](#34-authentication-인증-지표)
   - [API Performance (API 성능)](#35-api-performance-api-성능)
   - [Security (보안 인시던트)](#36-security-보안-인시던트)
   - [Logs (API 로그)](#37-logs-api-로그)
   - [Checklist (체크리스트)](#38-checklist-체크리스트)
   - [Test Scenarios (자동 테스트)](#39-test-scenarios-자동-테스트)
4. [외부 서비스 접속 정보](#4-외부-서비스-접속-정보)
5. [주요 기능 가이드](#5-주요-기능-가이드)
6. [문제 해결](#6-문제-해결)

---

## 1. 개요

Edge Auth Manager Dashboard는 엣지 디바이스 인증/인가 시스템을 모니터링하고 관리하기 위한 웹 기반 관리 도구입니다. Streamlit 프레임워크로 구축되었으며, Manager API와 mTLS로 통신합니다.

**주요 기능:**
- 디바이스 등록/승인/폐기 관리
- JWT 토큰 발급 및 인증 지표 모니터링
- API 성능 및 지연 시간 추적
- 보안 인시던트 감지 및 관리
- RabbitMQ 메시지 버스 상태 모니터링
- 자동화된 연속 테스트 실행

---

## 2. 접속 방법

### 대시보드

```
http://localhost:8501
```

### 사전 요구사항

시스템이 실행 중이어야 합니다:

```bash
# 인증서 생성 (최초 1회)
cd ops
python gen_certs.py --out ../certs
cd ..

# 서비스 시작
docker compose up --build -d
```

### 서비스 상태 확인

| 서비스 | URL | 용도 |
|--------|-----|------|
| Dashboard | `http://localhost:8501` | 관리 대시보드 |
| Manager API | `https://localhost:8443` | 인증 관리 API (mTLS 필요) |
| RabbitMQ Management | `http://localhost:15672` | 메시지 브로커 관리 UI |

---

## 3. 페이지별 설명

좌측 사이드바에서 각 페이지로 이동할 수 있습니다.

### 3.1 Home (메인)

**경로:** 사이드바 최상단

대시보드 진입 시 표시되는 메인 페이지입니다.

- **Quick Navigation**: 각 페이지에 대한 간략한 설명과 바로가기
- **System Requirements**: 시스템 요구사항 (Docker 28.4+, Kubernetes 1.30+)
- **Quick Status**: 총 디바이스 수, 승인 수, 24시간 요청 수, 활성 인시던트 수
- 승인 대기 중인 디바이스가 있으면 경고 메시지 표시
- 활성 보안 인시던트가 있으면 오류 메시지 표시

---

### 3.2 Overview (시스템 개요)

**경로:** 사이드바 > Overview

시스템 전체 상태를 한눈에 파악할 수 있는 대시보드입니다.

**상단 지표 카드:**
| 지표 | 설명 |
|------|------|
| Total Devices | 등록된 전체 디바이스 수 |
| Approved | 승인된 디바이스 수 |
| API Requests (24h) | 최근 24시간 API 요청 수 |
| Auth Success Rate | 인증 성공률 (%) |
| Active Incidents | 활성 보안 인시던트 수 |

**차트:**
- **Device Status Distribution**: 디바이스 상태별 분포 (Approved/Pending/Revoked) 파이 차트
- **Request Volume Over Time**: 시간대별 API 요청량 라인 차트

**System Health:**
- Uptime (가동 시간)
- Avg Latency (평균 지연 시간)
- Status (시스템 상태: OK / Warning / Error)

**Security Posture (보안 상태):**
- mTLS 적용 여부
- JWT TTL (토큰 유효 시간)
- RBAC Roles 수
- 차단된 토큰 수
- 마지막 JWT 시크릿 교체 일시

**컨트롤:**
- Time range: 1시간 / 6시간 / 24시간 / 7일 선택
- Auto-refresh: 30초 간격 자동 새로고침 토글

---

### 3.3 Devices (장치 관리)

**경로:** 사이드바 > Devices

디바이스의 전체 생명주기를 관리하는 핵심 페이지입니다.

**상단 지표:**
- Total Devices / Pending / Approved / Revoked

**Device List (디바이스 목록):**
- 상태별 필터링 (All / PENDING / APPROVED / REVOKED)
- 색상 코딩: PENDING(노란색), APPROVED(녹색), REVOKED(빨간색)
- 표시 항목: Namespace, Status, Agent Version, Last Seen

**Admin Actions (관리자 작업):**

디바이스를 선택한 후 아래 버튼으로 작업을 수행합니다:

| 버튼 | 기능 | 설명 |
|------|------|------|
| **Approve** | 디바이스 승인 | PENDING -> APPROVED 상태 변경 |
| **Revoke** | 디바이스 폐기 | 해당 디바이스의 인증 토큰 발급 차단 |
| **Issue Cert** | 인증서 발급 | 디바이스에 인증서 발급 상태 기록 |
| **Renew Cert** | 인증서 갱신 | 인증서 만료일 연장 |
| **Decommission** | 디바이스 해체 | 디바이스를 영구 제거하고 토큰 폐기 |
| **Transfer** | 디바이스 이관 | 다른 사이트/그룹으로 디바이스 이관 |

**Transfer (이관) 폼:**
- Transfer 버튼 클릭 시 폼 표시
- New site: 이관할 새 사이트명 (비워두면 유지)
- New group: 이관할 새 그룹명 (비워두면 유지)
- Reason: 이관 사유 (필수)

**Certificate Status (인증서 상태):**
- 선택된 디바이스의 인증서 상태 (ISSUED / REVOKED / UNKNOWN)
- 인증서 만료일

**Certificate Revocation List (CRL):**
- 폐기된 인증서 목록 표시
- `/cert/crl` 엔드포인트에서 조회

**Stale Devices (비활성 디바이스):**
- 24시간 이상 체크인하지 않은 디바이스 경고
- Namespace, Last Seen, Hours Stale 표시

**Message Bus (RabbitMQ):**
- RabbitMQ Management UI 링크
- 큐 정보 (`agent.metadata`)

---

### 3.4 Authentication (인증 지표)

**경로:** 사이드바 > Authentication

인증 성공/실패 추세를 분석하는 페이지입니다.

**Authentication Summary:**
- Total Attempts: 전체 인증 시도 횟수
- Successes: 성공 횟수
- Failures: 실패 횟수
- Success Rate: 성공률 (%)

**차트:**
- **Auth Events Over Time**: 시간대별 성공/실패 스택 바 차트
- **Failure Reasons**: 실패 원인별 파이 차트

**Events by Type:**
- 이벤트 유형별 횟수 (TOKEN_ISSUED, TOKEN_DENIED, VALIDATION_OK 등)

**Per-Device Authentication Stats:**
- 디바이스별 인증 통계 테이블
- 실패가 있는 디바이스는 노란색 하이라이트

**Failure Analysis:**
- 실패율 10% 초과: 빨간 경고 + 권장 조치
- 실패율 5~10%: 노란 경고
- 5% 미만: 정상 표시

**JWT Security Status:**
- JWT Algorithm (HS256)
- Token TTL (토큰 유효 시간)
- HMAC Algorithm (SHA-256)
- Blocked Tokens (차단된 토큰 수)
- 마지막 JWT 시크릿 교체 일시
- **RBAC Permission Matrix**: 역할별 허용 경로 목록 (확장 가능)

---

### 3.5 API Performance (API 성능)

**경로:** 사이드바 > API Performance

API 엔드포인트별 성능 지표를 추적하는 페이지입니다.

- 요청 지연 시간 (latency) 추적
- 에러율 분석
- 엔드포인트별 통계

---

### 3.6 Security (보안 인시던트)

**경로:** 사이드바 > Security

보안 인시던트를 감지, 조회, 관리하는 페이지입니다.

**Severity 카운터:**
- Critical / High / Medium / Low / Total Active

**차트:**
- **Incidents by Type**: 인시던트 유형별 바 차트
- **Severity Distribution**: 심각도별 파이 차트

**Incident Log:**
- 인시던트 목록 (확장 가능)
- 심각도별 색상 표시 (CRITICAL=빨강, HIGH=주황, MEDIUM=노랑, LOW=초록)
- 각 인시던트에 대해: Type, Severity, Description, Namespace, Time, Status
- **Resolve** 버튼으로 인시던트 해결 처리

**인시던트 유형:**

| 유형 | 설명 |
|------|------|
| AUTH_FAILURE_BURST | 짧은 시간 내 대량 인증 실패 (무차별 대입 공격 의심) |
| STALE_DEVICE | 장시간 체크인하지 않은 승인 디바이스 |
| CERT_EXPIRED | 인증서 만료 |
| REVOKED_ACCESS_ATTEMPT | 폐기된 디바이스의 인증 시도 |
| DEVICE_DECOMMISSIONED | 관리자에 의해 해체된 디바이스 |
| DEVICE_TRANSFERRED | 다른 사이트/그룹으로 이관된 디바이스 |
| SUSPICIOUS_ACTIVITY | 기타 의심스러운 활동 |

**Time range**: 1일 / 3일 / 7일 / 14일 / 30일

---

### 3.7 Logs (API 로그)

**경로:** 사이드바 > Logs

Manager API의 요청 로그를 조회하고 필터링하는 페이지입니다.

**필터 옵션:**
- Time range: 1시간 / 6시간 / 24시간 / 7일
- Limit: 50 / 100 / 200 / 500건
- Status filter: All / Success (2xx) / Client Error (4xx) / Server Error (5xx)

**표시 항목:**
- Timestamp, Method, Path, Status Code, Latency, Client CN, Correlation ID

---

### 3.8 Checklist (체크리스트)

**경로:** 사이드바 > Checklist

프로토타입 개발 체크리스트를 구현 상태와 매핑하는 페이지입니다.

**두 가지 분류:**

**A. Dashboard-Verifiable (대시보드 확인 가능):**
- 대시보드 UI에서 직접 확인 가능한 항목
- 각 항목에 "어떻게 확인하는지" 설명 포함
- 해당 대시보드 페이지로 바로가기 버튼

**B. Code-Verifiable (코드 확인 필요):**
- 대시보드에서는 볼 수 없는 내부 메커니즘
- 실제 소스 코드 스니펫과 설명 인라인 표시
- 예: async 이벤트 루프, retry/backoff, mTLS 핸드셰이크, AMQP 재연결, 로컬 버퍼 등

**카테고리:**
1. Lightweight Agent Security Module (에이전트 보안 모듈)
2. Asynchronous Event Loop, Retry/Backoff, mTLS (비동기/재시도/mTLS)
3. Authentication Module API (인증 모듈 API)
4. Network Segmentation & PKI (네트워크 분리 & PKI)
5. Container Images, Initial Setup (컨테이너 & 초기 설정)

---

### 3.9 Test Scenarios (자동 테스트)

**경로:** 사이드바 > Test Scenarios

4개 요구사항 영역을 지속적으로 검증하는 자동화 테스트 시스템입니다.

**Control Panel (제어판):**
- **Start / Stop** 버튼: 연속 테스트 시작/중지
- **Interval**: 테스트 주기 설정 (10~300초, 기본 30초)
- **Status**: 실행 상태 + 사이클 카운터

**테스트 카테고리 (4개):**

| 카테고리 | 테스트 내용 |
|----------|------------|
| Agent Security Module | 디바이스 등록, 중복 감지, 네임스페이스 검증 |
| Async/mTLS/Session | mTLS 헬스체크, 세션 재사용, 동시 요청, 응답 지연 |
| Auth Module APIs | 디바이스 승인, 토큰 발급/검증, 인증서 발급/갱신/폐기, RBAC |
| Message Bus | RabbitMQ 상태, 큐 확인, TLS 연결, 권한 제한 |

**탭:**

| 탭 | 내용 |
|----|------|
| **Current Cycle** | 현재 테스트 결과 (총/통과/실패/에러/성공률) + 색상 코딩 테이블 |
| **Historical Stats** | 누적 통계 + 성공률 추세 라인 차트 |
| **Category Breakdown** | 카테고리별 성공률 테이블 + 바 차트 |
| **Test Log** | 최근 결과 필터링 (상태별/카테고리별), 최대 100건 |
| **Security Config** | JWT 설정, RBAC 매트릭스, CRL, HMAC 정보 |

---

## 4. 외부 서비스 접속 정보

### RabbitMQ Management UI

```
URL: http://localhost:15672
ID:  isl
PW:  wjdqhqhghdusrntlf1!
```

**주요 확인 항목:**
- Queues: `agent.metadata` 큐 상태 및 메시지 수
- Connections: 에이전트 TLS 연결 상태
- Channels: 활성 채널 수

### Manager API

```
URL: https://localhost:8443
```

mTLS 인증서가 필요합니다. `certs/admin/` 디렉토리의 인증서를 사용합니다.

**주요 엔드포인트:**
| 엔드포인트 | 메서드 | 용도 |
|-----------|--------|------|
| `/healthz` | GET | 서비스 상태 확인 |
| `/device/register` | POST | 디바이스 등록 |
| `/device/list` | GET | 디바이스 목록 조회 |
| `/device/approve` | POST | 디바이스 승인 |
| `/device/revoke` | POST | 디바이스 폐기 |
| `/device/decommission` | POST | 디바이스 해체 |
| `/device/transfer` | POST | 디바이스 이관 |
| `/auth/token` | POST | JWT 토큰 발급 |
| `/auth/validate` | POST | 토큰 검증 |
| `/cert/issue` | POST | 인증서 발급 |
| `/cert/renew` | POST | 인증서 갱신 |
| `/cert/revoke` | POST | 인증서 폐기 |
| `/cert/status` | GET | 인증서 상태 조회 |
| `/cert/crl` | GET | 인증서 폐기 목록 (CRL) |
| `/admin/rbac-matrix` | GET | RBAC 권한 매트릭스 |
| `/admin/security-config` | GET | 보안 설정 정보 |
| `/admin/rotate-jwt-secret` | POST | JWT 시크릿 교체 |
| `/admin/revoke-tokens` | POST | 토큰 차단 |

---

## 5. 주요 기능 가이드

### 5.1 디바이스 승인 절차

1. **Devices** 페이지로 이동
2. 상태 필터를 **PENDING**으로 설정
3. 승인할 디바이스의 namespace 선택
4. **Approve** 버튼 클릭
5. 성공 메시지 확인 후 목록에서 APPROVED로 변경됨

### 5.2 디바이스 폐기 (Revoke)

1. **Devices** 페이지에서 대상 디바이스 선택
2. **Revoke** 버튼 클릭
3. 해당 디바이스는 더 이상 JWT 토큰을 발급받을 수 없음
4. 에이전트가 다음 토큰 갱신 시 REVOKED 상태를 감지하고 중지

### 5.3 디바이스 해체 (Decommission)

1. **Devices** 페이지에서 대상 디바이스 선택
2. **Decommission** 버튼 클릭
3. 디바이스가 영구적으로 제거되고 모든 토큰이 폐기됨
4. Security 페이지에 DEVICE_DECOMMISSIONED 인시던트 기록

### 5.4 디바이스 이관 (Transfer)

1. **Devices** 페이지에서 대상 디바이스 선택
2. **Transfer** 버튼 클릭
3. 이관 폼에서 새 사이트/그룹 입력 및 사유 작성
4. **Submit Transfer** 클릭
5. 네임스페이스가 변경되고 기존 토큰이 폐기됨

### 5.5 자동 테스트 실행

1. **Test Scenarios** 페이지로 이동
2. Interval 설정 (기본 30초)
3. **Start Continuous Testing** 버튼 클릭
4. Current Cycle 탭에서 실시간 결과 확인
5. Historical Stats 탭에서 추세 확인
6. 중지 시 **Stop Testing** 버튼 클릭

### 5.6 보안 인시던트 처리

1. **Security** 페이지로 이동
2. CRITICAL/HIGH 인시던트 우선 확인 (자동 펼침)
3. 인시던트 상세 정보 확인 (Type, Namespace, Description)
4. 조치 완료 후 **Resolve** 버튼 클릭

### 5.7 인증 장애 분석

1. **Authentication** 페이지로 이동
2. Success Rate가 95% 이하이면 주의
3. Failure Reasons 차트에서 주요 실패 원인 확인
4. Per-Device 테이블에서 문제 디바이스 식별
5. Failure Analysis 섹션의 권장 조치 확인:
   - 인증서 만료/폐기 여부 점검
   - 디바이스 등록 상태 확인
   - 네트워크 연결 상태 점검

---

## 6. 문제 해결

### 대시보드에 "Cannot reach manager API" 오류

- Manager 컨테이너 실행 확인: `docker compose ps`
- Manager 로그 확인: `docker compose logs manager`
- 인증서가 정상 생성되었는지 확인: `ls certs/admin/`

### RabbitMQ Management UI 접속 불가

- 컨테이너 실행 확인: `docker compose ps rabbitmq`
- 포트 바인딩 확인: `docker compose ps`에서 `0.0.0.0:15672->15672` 확인
- 로그 확인: `docker compose logs rabbitmq`

### 디바이스가 PENDING 상태에서 변하지 않음

- Dashboard의 **Devices** 페이지에서 **Approve** 버튼 클릭
- `AUTO_APPROVE` 환경 변수가 `true`로 설정되어 있는지 확인

### 테스트가 모두 실패하는 경우

- Manager API가 정상 동작하는지 확인: `docker compose logs manager`
- RabbitMQ가 healthy인지 확인: `docker compose ps`
- 인증서가 만료되지 않았는지 확인

### 에이전트가 연결되지 않음

- 에이전트 로그 확인: `docker compose logs agent-001`
- RabbitMQ 사용자/비밀번호 확인
- mTLS 인증서 경로 확인

---

*Edge Auth Manager Prototype - Dashboard Guide v1.0.0*

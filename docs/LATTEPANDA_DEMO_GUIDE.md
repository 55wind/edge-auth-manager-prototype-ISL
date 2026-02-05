# LattePanda 2대 + PC 시연 가이드

이 문서는 PC 1대(서버)와 LattePanda 2대(에이전트)를 사용하여 Edge Authentication Manager 시스템을 실제 환경에서 시연하는 방법을 설명합니다.

## 시스템 구성도

```
                         ┌─────────────────────────────────────┐
                         │        네트워크 (동일 공유기)         │
                         └─────────────────────────────────────┘
                                          │
           ┌──────────────────────────────┼──────────────────────────────┐
           │                              │                              │
           ▼                              ▼                              ▼
┌─────────────────────┐      ┌─────────────────────┐      ┌─────────────────────┐
│   LattePanda #1     │      │   LattePanda #2     │      │        PC           │
│   (Agent Node)      │      │   (Agent Node)      │      │   (Server Node)     │
├─────────────────────┤      ├─────────────────────┤      ├─────────────────────┤
│                     │      │                     │      │                     │
│  ┌───────────────┐  │      │  ┌───────────────┐  │      │  ┌───────────────┐  │
│  │  Agent #1     │  │      │  │  Agent #2     │  │      │  │ Auth Manager  │  │
│  │  (온도 센서)   │──┼──────┼──┼───────────────┼──┼──────┼─►│   (8443)      │  │
│  └───────────────┘  │ mTLS │  └───────────────┘  │ mTLS │  └───────────────┘  │
│         │          │      │         │          │      │                     │
│         │          │      │         │          │      │  ┌───────────────┐  │
│         │          │      │         │          │      │  │   RabbitMQ    │  │
│         └──────────┼──────┼─────────┴──────────┼──────┼─►│   (5671)      │  │
│           AMQPS    │      │         AMQPS      │      │  └───────────────┘  │
│                     │      │                     │      │         │          │
│  latte-001         │      │  latte-002         │      │  ┌──────┴────────┐  │
│  (습도 센서)        │      │  (습도 센서)        │      │  │   Dashboard   │  │
│                     │      │                     │      │  │   (8501)      │  │
│                     │      │                     │      │  └───────────────┘  │
└─────────────────────┘      └─────────────────────┘      └─────────────────────┘
```

## 역할 분담

| 장비 | 역할 | 실행 서비스 | 설명 |
|------|------|------------|------|
| **PC** | Server | Manager, RabbitMQ, Dashboard | 인증/메시지 서버 + 모니터링 |
| **LattePanda #1** | Agent | Edge Agent (latte-001) | 온도 센서 데이터 전송 |
| **LattePanda #2** | Agent | Edge Agent (latte-002) | 습도 센서 데이터 전송 |

---

## 시연에서 볼 수 있는 것

1. **두 Agent가 동시에 Server에 등록 요청**
2. **Dashboard에서 두 디바이스 승인**
3. **두 Agent가 각각 센서 데이터를 실시간 전송**
4. **Dashboard에서 두 Agent의 데이터를 동시에 모니터링**
5. **특정 Agent Revoke 시 해당 Agent만 종료**

---

## 사전 준비물

### 하드웨어
- PC 1대 (서버 역할, Docker 실행)
- LattePanda 2대 (에이전트 역할)
- 공유기/스위치 (3대 모두 동일 네트워크)

### 소프트웨어
| 장비 | 필요 소프트웨어 |
|------|----------------|
| PC | Docker, Docker Compose, Python 3.10+, Git |
| LattePanda #1 | Docker, Docker Compose |
| LattePanda #2 | Docker, Docker Compose |

---

## 1단계: PC (Server) 설정

### 1.1 프로젝트 다운로드

```bash
git clone <repository-url> edge-auth-manager-prototype
cd edge-auth-manager-prototype
```

### 1.2 인증서 생성

```bash
cd ops
python gen_certs.py --out ../certs
cd ..
```

### 1.3 서버 시작

```bash
# Linux/Mac
chmod +x scripts/start-server.sh
./scripts/start-server.sh

# Windows
scripts\start-server.bat

# 또는 직접 실행
docker compose -f docker-compose.server.yml up --build -d
```

### 1.4 서버 상태 확인

```bash
docker compose -f docker-compose.server.yml ps

# 예상 출력:
# NAME              STATUS
# auth_dashboard    Up
# auth_manager      Up (healthy)
# rabbitmq_tls      Up (healthy)
```

### 1.5 PC의 IP 확인 (중요!)

```bash
# Linux/Mac
./scripts/show-ip.sh

# Windows
scripts\show-ip.bat

# 또는 직접 확인
# Linux: ip route get 1 | awk '{print $7; exit}'
# Windows: ipconfig | findstr "IPv4"
```

**출력 예시:**
```
=== 현재 IP 주소 ===

이 장비의 IP: 192.168.0.100

Dashboard 접속 URL:
  http://192.168.0.100:8501
```

> **이 IP를 LattePanda 2대에 알려주세요!**

### 1.6 인증서를 LattePanda에 복사

**두 LattePanda 모두에 `certs/` 폴더를 복사해야 합니다.**

```bash
# 방법 1: scp 사용
scp -r certs user@<LattePanda1-IP>:~/edge-auth-manager-prototype/
scp -r certs user@<LattePanda2-IP>:~/edge-auth-manager-prototype/

# 방법 2: USB 드라이브
# certs 폴더를 USB에 복사 후 각 LattePanda로 이동
```

### 1.7 방화벽 설정 (필요시)

```bash
# Linux (Ubuntu)
sudo ufw allow 8443/tcp   # Manager API
sudo ufw allow 8501/tcp   # Dashboard
sudo ufw allow 5671/tcp   # RabbitMQ TLS

# Windows
netsh advfirewall firewall add rule name="EdgeAuth-Manager" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="EdgeAuth-Dashboard" dir=in action=allow protocol=TCP localport=8501
netsh advfirewall firewall add rule name="EdgeAuth-RabbitMQ" dir=in action=allow protocol=TCP localport=5671
```

---

## 2단계: LattePanda #1 (Agent latte-001) 설정

### 2.1 프로젝트 다운로드

```bash
git clone <repository-url> edge-auth-manager-prototype
cd edge-auth-manager-prototype
```

### 2.2 인증서 복사 확인

PC에서 복사한 인증서가 있는지 확인합니다.

```bash
ls certs/
# 출력: agent/  ca.crt  admin/  manager/  rabbitmq/  ...
```

### 2.3 Agent 시작

**PC에서 확인한 IP를 입력합니다.**

```bash
# Linux (IP 입력 프롬프트)
chmod +x scripts/start-agent-auto.sh
./scripts/start-agent-auto.sh

# Windows
scripts\start-agent-auto.bat
```

```
Server(PC)의 IP 주소를 입력하세요: 192.168.0.100
```

> Agent #1은 `latte-001` ID와 `temperature` 센서로 실행됩니다.

---

## 3단계: LattePanda #2 (Agent latte-002) 설정

### 3.1 프로젝트 다운로드

```bash
git clone <repository-url> edge-auth-manager-prototype
cd edge-auth-manager-prototype
```

### 3.2 인증서 복사 확인

```bash
ls certs/
```

### 3.3 docker-compose.agent.yml 수정

**두 번째 Agent를 위해 설정을 수정합니다.**

`docker-compose.agent.yml` 파일을 열고 다음과 같이 수정:

```yaml
services:
  agent-latte-001:
    # ...
    command: >
      python -m agent.run
      --device-id latte-002          # 변경: latte-001 → latte-002
      --site factory-demo
      --group sensors
    environment:
      # ...
      AGENT_SENSOR_TYPE: "humidity"  # 변경: temperature → humidity
```

또는 별도의 docker-compose 파일 사용:

```bash
# docker-compose.agent2.yml 생성 (아래 참조)
```

### 3.4 Agent 시작

```bash
# Linux
./scripts/start-agent-auto.sh

# Windows
scripts\start-agent-auto.bat
```

```
Server(PC)의 IP 주소를 입력하세요: 192.168.0.100
```

---

## 4단계: PC에서 Dashboard 모니터링

### 4.1 Dashboard 접속

PC의 웹 브라우저에서:

```
http://localhost:8501
```

또는 다른 기기에서:
```
http://<PC-IP>:8501
```

### 4.2 두 Agent 확인

**Devices 페이지에서:**
- `latte-001` (PENDING) - LattePanda #1
- `latte-002` (PENDING) - LattePanda #2

두 디바이스 모두 표시되어야 합니다.

---

## 5단계: 시연 시나리오

### 시나리오 1: 두 Agent 동시 등록 및 승인

#### Step 1: Dashboard 준비 (PC)
1. 브라우저에서 `http://localhost:8501` 접속
2. **"Devices"** 페이지로 이동

#### Step 2: 두 Agent 시작 (LattePanda #1, #2 동시에)

**LattePanda #1:**
```bash
./scripts/start-agent-auto.sh
# Server IP 입력: 192.168.0.100
```

**LattePanda #2:**
```bash
./scripts/start-agent-auto.sh
# Server IP 입력: 192.168.0.100
```

#### Step 3: Dashboard에서 두 디바이스 확인
```
┌─────────────────────────────────────────────────────────────┐
│ Devices                                                     │
├─────────────────────────────────────────────────────────────┤
│ Device ID    │ Site         │ Status   │ Sensor   │ Action │
├──────────────┼──────────────┼──────────┼──────────┼────────┤
│ latte-001    │ factory-demo │ PENDING  │ temp     │ Approve│
│ latte-002    │ factory-demo │ PENDING  │ humidity │ Approve│
└─────────────────────────────────────────────────────────────┘
```

#### Step 4: 두 디바이스 모두 승인
1. `latte-001` → **Approve** 클릭
2. `latte-002` → **Approve** 클릭

#### Step 5: 실시간 데이터 확인
두 Agent 모두 데이터 전송 시작:
- `latte-001`: 온도 데이터 (temperature_c)
- `latte-002`: 습도 데이터 (humidity_pct)

---

### 시나리오 2: 실시간 데이터 모니터링

Dashboard에서 두 Agent의 센서 데이터를 동시에 확인:

```json
// latte-001 (온도)
{
  "device_id": "latte-001",
  "sensor_type": "temperature",
  "metrics": { "temperature_c": 23.45 }
}

// latte-002 (습도)
{
  "device_id": "latte-002",
  "sensor_type": "humidity",
  "metrics": { "humidity_pct": 52.30 }
}
```

---

### 시나리오 3: 특정 Agent만 Revoke

#### Step 1: latte-001만 Revoke
Dashboard에서 `latte-001` → **Revoke** 클릭

#### Step 2: 결과 확인
- **LattePanda #1**: Agent 종료 (`Device REVOKED. Stopping agent.`)
- **LattePanda #2**: 정상 동작 계속

#### Step 3: Dashboard 확인
```
│ latte-001    │ factory-demo │ REVOKED  │ temp     │        │
│ latte-002    │ factory-demo │ APPROVED │ humidity │ Revoke │
```

---

### 시나리오 4: 네트워크 장애 시뮬레이션

#### Step 1: LattePanda #1의 네트워크 차단
```bash
# LattePanda #1에서
sudo iptables -A OUTPUT -d <PC-IP> -j DROP
```

#### Step 2: Dashboard 확인
- `latte-001`: 데이터 수신 중단
- `latte-002`: 정상 데이터 수신 계속

#### Step 3: 네트워크 복구
```bash
sudo iptables -D OUTPUT -d <PC-IP> -j DROP
```

#### Step 4: 자동 복구 확인
- `latte-001`: 버퍼에 저장된 데이터 전송 재개

---

## LattePanda #2용 docker-compose 파일

`docker-compose.agent2.yml` 파일을 생성하여 사용할 수 있습니다:

```yaml
services:
  agent-latte-002:
    build:
      context: .
      dockerfile: services/agent/Dockerfile
    container_name: edge_agent_latte_002
    command: >
      python -m agent.run
      --device-id latte-002
      --site factory-demo
      --group sensors
    environment:
      MANAGER_BASE_URL: "https://${SERVER_IP}:8443"
      AMQP_URL: "amqps://isl:${RABBITMQ_EDGE_PASSWORD:-wjdqhqhghdusrntlf1!}@${SERVER_IP}:5671/"
      CERTS_DIR: "/certs"
      AGENT_BUFFER_DIR: "/buffer"
      AGENT_SENSOR_TYPE: "humidity"
    volumes:
      - ./certs:/certs:ro
      - ./data/agent_buffer_002:/buffer
    extra_hosts:
      - "manager.local:${SERVER_IP}"
      - "rabbitmq.local:${SERVER_IP}"
    restart: unless-stopped
```

실행:
```bash
SERVER_IP=192.168.0.100 docker compose -f docker-compose.agent2.yml up --build
```

---

## 트러블슈팅

### 문제: Agent가 Server에 연결 실패

**확인사항:**
1. PC의 IP 주소 정확한지 확인
2. PC 방화벽에서 8443, 5671 포트 허용
3. 인증서가 올바르게 복사되었는지 확인

### 문제: Dashboard에서 한 Agent만 보임

**확인사항:**
1. 두 Agent의 device-id가 다른지 확인 (`latte-001`, `latte-002`)
2. 두 Agent 모두 실행 중인지 확인

### 문제: 두 Agent가 같은 데이터 전송

**확인사항:**
1. `AGENT_SENSOR_TYPE` 환경변수 확인
   - LattePanda #1: `temperature`
   - LattePanda #2: `humidity`

---

## 시연 전 체크리스트

### PC (Server)
- [ ] Docker 설치 완료
- [ ] 인증서 생성 완료
- [ ] 서비스 시작 완료 (3개 모두 running)
- [ ] IP 확인 완료 (`./scripts/show-ip.sh`)
- [ ] 방화벽 설정 완료 (8443, 8501, 5671)
- [ ] 인증서를 LattePanda 2대에 복사 완료

### LattePanda #1 (Agent latte-001)
- [ ] Docker 설치 완료
- [ ] `certs/` 폴더 복사 완료
- [ ] PC IP 확인

### LattePanda #2 (Agent latte-002)
- [ ] Docker 설치 완료
- [ ] `certs/` 폴더 복사 완료
- [ ] device-id를 `latte-002`로 변경
- [ ] sensor type을 `humidity`로 변경
- [ ] PC IP 확인

### 연결 테스트
- [ ] LattePanda #1 → PC ping 성공
- [ ] LattePanda #2 → PC ping 성공

---

## 빠른 참조 명령어

### PC (Server)
```bash
# IP 확인
./scripts/show-ip.sh

# 시작
docker compose -f docker-compose.server.yml up -d

# 로그
docker compose -f docker-compose.server.yml logs -f

# 중지
docker compose -f docker-compose.server.yml down
```

### LattePanda #1 (Agent latte-001)
```bash
# 시작 (IP 입력)
./scripts/start-agent-auto.sh

# 로그
docker compose -f docker-compose.agent.yml logs -f

# 중지
docker compose -f docker-compose.agent.yml down
```

### LattePanda #2 (Agent latte-002)
```bash
# 시작 (device-id, sensor 변경 후)
SERVER_IP=<PC-IP> docker compose -f docker-compose.agent2.yml up

# 또는 환경변수로
export SERVER_IP=<PC-IP>
docker compose -f docker-compose.agent2.yml up
```

---

## 시연 흐름 요약

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            시연 흐름도                                       │
└─────────────────────────────────────────────────────────────────────────────┘

[1] 준비 (PC)
    Server 시작 ──► IP 확인 ──► 인증서 복사 (→ LattePanda 2대)

[2] Agent 시작
    LattePanda #1: latte-001 시작 ──┐
                                    ├──► Dashboard: 2개 PENDING 확인
    LattePanda #2: latte-002 시작 ──┘

[3] 승인
    Dashboard: latte-001 Approve ──► Dashboard: latte-002 Approve

[4] 실시간 모니터링
    ┌─ latte-001: 온도 데이터 ──┐
    │                          ├──► Dashboard: 실시간 확인
    └─ latte-002: 습도 데이터 ──┘

[5] 보안 시연 (선택)
    Dashboard: latte-001 Revoke ──► LattePanda #1만 종료, #2는 계속 동작
```

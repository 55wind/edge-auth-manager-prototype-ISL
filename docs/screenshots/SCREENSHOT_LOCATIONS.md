# 스크린샷 위치 매핑

각 스크린샷이 대시보드 어디에서 촬영되었는지 정리한 문서입니다.

---

## 대시보드 페이지 목록

| 페이지 | URL | 설명 |
|--------|-----|------|
| Home | http://localhost:8501 | 시스템 개요 및 Quick Navigation |
| Overview | http://localhost:8501/Overview | System Overview, Key Metrics |
| Devices | http://localhost:8501/Devices | Device Management, Admin Actions |
| Authentication | http://localhost:8501/Authentication | JWT, Token Events, RBAC |
| API Performance | http://localhost:8501/API_Performance | 성능 메트릭스 |
| Security | http://localhost:8501/Security | Security Incidents |
| Logs | http://localhost:8501/Logs | API Logs |
| Checklist | http://localhost:8501/Checklist | Dashboard/Code Verifiable Items |
| Test Scenarios | http://localhost:8501/Test_Scenarios | Continuous Test |

**외부 UI:**
| 서비스 | URL | 설명 |
|--------|-----|------|
| RabbitMQ Management | http://localhost:15672 | 메시지 브로커 관리 UI |

---

## 스크린샷 위치 매핑

### Home 페이지
| 파일명 | 위치 |
|--------|------|
| `42_home_page.png` | Home 페이지 > 전체 화면 |

---

### Overview 페이지
| 파일명 | 위치 |
|--------|------|
| `20_overview_metrics.png` | Overview 페이지 > "Key Metrics" 섹션 |
| `29_system_health.png` | Overview 페이지 > "Key Metrics" 섹션 (동일) |
| `57_manager_overview.png` | Overview 페이지 > 전체 화면 |

---

### Devices 페이지
| 파일명 | 위치 |
|--------|------|
| `01_namespace_device_list.png` | Devices 페이지 > "Device List" 섹션 |
| `02_status_pending.png` | Devices 페이지 > "Device List" 섹션 (PENDING 상태 강조) |
| `05_admin_actions.png` | Devices 페이지 > "Admin Actions" 섹션 |
| `07_network_overview.png` | Devices 페이지 > 네트워크 개요 |
| `16_crl_section.png` | Devices 페이지 > "Certificate Revocation List (CRL)" 섹션 |
| `17_cert_status.png` | Devices 페이지 > "Certificate Status" 섹션 |
| `30_device_registration.png` | Devices 페이지 > "Device List" 섹션 |
| `31_device_lastseen.png` | Devices 페이지 > "Device List" 섹션 > "Last Seen" 컬럼 |
| `33_cert_actions.png` | Devices 페이지 > "Admin Actions" 섹션 > Cert 버튼들 |

---

### Authentication 페이지
| 파일명 | 위치 |
|--------|------|
| `10_jwt_security_status.png` | Authentication 페이지 > "JWT Security Status" 섹션 |
| `11_auth_summary.png` | Authentication 페이지 > 인증 요약 |
| `12_token_events.png` | Authentication 페이지 > "Events by Type" 섹션 |
| `13_rbac_matrix.png` | Authentication 페이지 > "RBAC Permission Matrix" 확장 섹션 |
| `14_hmac_algorithm.png` | Authentication 페이지 > "JWT Security Status" > HMAC Algorithm |
| `18_last_rotation.png` | Authentication 페이지 > "JWT Security Status" 섹션 (Rotation 정보) |
| `19_security_config.png` | Authentication 페이지 > 보안 설정 종합 |
| `25_auth_events_timeline.png` | Authentication 페이지 > 이벤트 타임라인 차트 |
| `36_auth_failure_analysis.png` | Authentication 페이지 > "Failure Analysis" 섹션 |

---

### Security 페이지
| 파일명 | 위치 |
|--------|------|
| `26_security_incidents.png` | Security 페이지 > "Active Incidents by Severity" 및 "Incidents by Type" 섹션 |

---

### Logs 페이지
| 파일명 | 위치 |
|--------|------|
| `27_logs_page.png` | Logs 페이지 > "Request Logs" 테이블 |
| `28_logs_filter.png` | Logs 페이지 > 필터 옵션 (Time range, Status filter) |

---

### Checklist 페이지

#### Dashboard-Verifiable Items 섹션
| 파일명 | 위치 |
|--------|------|
| `43_checklist_dashboard.png` | Checklist 페이지 > "A. Dashboard-Verifiable Items" 섹션 |
| `44_checklist_code.png` | Checklist 페이지 > "A. Dashboard-Verifiable Items" 테이블 |
| `54_crl_ocsp_section.png` | Checklist 페이지 > "A. Dashboard-Verifiable Items" > "5. PKI/Secret Management" |

#### Code-Verifiable Items 섹션 (B 섹션)
| 파일명 | 위치 |
|--------|------|
| `50_checklist_network_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Retry / exponential backoff with jitter" 확장 |
| `51_checklist_container_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Docker network segmentation" 확장 |
| `52_checklist_mtls_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "mTLS handshake & session" 확장 |
| `53_intermediate_ca_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Intermediate CA" 확장 |
| `55_agent_async_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Async event loop" 확장 |
| `55_agent_amqp_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "TLS-secured AMQP connection" 확장 |
| `58_register_retry_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Retry / exponential backoff" 확장 |
| `59_jwt_token_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "JWT token issuance" 확장 |
| `60_buffer_reconnect_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Local buffer & reconnect" 확장 |
| `61_full_auth_flow_code.png` | Checklist 페이지 > "B. Code-Verifiable Items" > "Full auth flow" 확장 |

#### Exception Handling Flows 섹션 (6번 섹션)
| 파일명 | 위치 |
|--------|------|
| `64_token_expiration_code.png` | Checklist 페이지 > "6. Exception Handling Flows" > "Token expiration auto-refresh" 확장 |
| `65_duplicate_registration_code.png` | Checklist 페이지 > "6. Exception Handling Flows" > "Duplicate registration handling" 확장 |
| `66_connection_drop_code.png` | Checklist 페이지 > "6. Exception Handling Flows" > "Connection drop handling" 확장 |

---

### Test Scenarios 페이지
| 파일명 | 위치 |
|--------|------|
| `08_test_mtls.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > 테스트 결과 테이블 |
| `15_test_rbac.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > Auth Module APIs 테스트 |
| `23_test_messagebus.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > Message Bus 테스트 |
| `24_test_agent_security.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > Agent Security Module 테스트 |
| `32_test_registration.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > Registration 테스트 |
| `35_test_auth_apis.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > Auth Module APIs 테스트 |
| `39_test_rmq_health.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > RabbitMQ Health 테스트 |
| `40_test_rmq_permissions.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > RabbitMQ Permissions 테스트 |
| `45_test_current_cycle.png` | Test Scenarios 페이지 > "Current Cycle" 탭 > 전체 화면 |
| `46_test_historical.png` | Test Scenarios 페이지 > "Historical Stats" 탭 |
| `47_test_category.png` | Test Scenarios 페이지 > "Category Breakdown" 탭 |
| `48_test_log.png` | Test Scenarios 페이지 > "Test Log" 탭 |

---

### RabbitMQ Management UI (외부)
| 파일명 | 위치 |
|--------|------|
| `21_rabbitmq_queues.png` | RabbitMQ Management > "Queues and Streams" 탭 |
| `22_rabbitmq_overview.png` | RabbitMQ Management > "Overview" 탭 |
| `37_rabbitmq_tls.png` | RabbitMQ Management > "Connections" 탭 (TLS 연결) |
| `38_queue_metadata.png` | RabbitMQ Management > "Queues" > agent.metadata 큐 상세 |
| `56_gateway_rabbitmq.png` | RabbitMQ Management > "Overview" 탭 > 전체 화면 |

---

### 생성된 다이어그램 (matplotlib)
| 파일명 | 생성 스크립트 | 설명 |
|--------|--------------|------|
| `61_auth_flow_sequence.png` | `ops/generate_sequence_diagram.py` | 인증 흐름 시퀀스 다이어그램 |
| `62_sequence_legend.png` | `ops/generate_legend.py` | 시퀀스 다이어그램 범례 |
| `63_exception_flows.png` | `ops/generate_exception_flow.py` | 예외 처리 흐름도 (만료/중복/단절) |
| `67_autoscale_architecture.png` | `ops/generate_autoscale_diagram.py` | Stateless 오토스케일 아키텍처 |

---

## 빠른 참조

### 페이지별 스크린샷 개수
| 페이지 | 스크린샷 수 |
|--------|------------|
| Home | 1 |
| Overview | 3 |
| Devices | 9 |
| Authentication | 9 |
| Security | 1 |
| Logs | 2 |
| Checklist | 15 |
| Test Scenarios | 12 |
| RabbitMQ (외부) | 5 |
| 생성 다이어그램 | 4 |
| **총계** | **61** |

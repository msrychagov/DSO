# Data Flow Diagram (DFD)

## Обзор
Данный документ содержит Data Flow Diagram для SecDev Course Project с обозначением границ доверия и потоков данных.

## Основная диаграмма

```mermaid
flowchart TD
    %% External entities
    U[👤 User/Client]
    EXT[🌐 External Services]

    %% Trust Boundary: Edge
    subgraph Edge["🔒 Trust Boundary: Edge"]
        GW[🚪 API Gateway]
        LB[⚖️ Load Balancer]
    end

    %% Trust Boundary: Core
    subgraph Core["🔒 Trust Boundary: Core"]
        AUTH[🔐 Auth Service]
        API[📡 API Service]
        LOG[📝 Logging Service]
    end

    %% Trust Boundary: Data
    subgraph Data["🔒 Trust Boundary: Data"]
        DB[(🗄️ Database)]
        CACHE[(⚡ Cache)]
        VAULT[🔑 Secret Vault]
    end

    %% Data flows
    U -->|F1: HTTPS/TLS 1.3+| GW
    GW -->|F2: mTLS| LB
    LB -->|F3: Internal| AUTH
    LB -->|F4: Internal| API
    AUTH -->|F5: Encrypted| DB
    API -->|F6: Encrypted| DB
    API -->|F7: Internal| CACHE
    AUTH -->|F8: Secure| VAULT
    API -->|F9: Structured| LOG
    LOG -->|F10: Encrypted| DB

    %% External connections
    EXT -->|F11: HTTPS| GW

    %% Styling
    style U fill:#e1f5fe
    style EXT fill:#e1f5fe
    style Edge stroke:#ff9800,stroke-width:3px
    style Core stroke:#4caf50,stroke-width:3px
    style Data stroke:#f44336,stroke-width:3px
    style GW fill:#fff3e0
    style AUTH fill:#e8f5e8
    style API fill:#e8f5e8
    style DB fill:#ffebee
    style VAULT fill:#ffebee
```

## Список потоков данных

| ID | Откуда → Куда | Канал/Протокол | Данные/PII | Комментарий |
|----|---------------|-----------------|------------|-------------|
| F1 | User → API Gateway | HTTPS/TLS 1.3+ | Credentials, PII | Публичный доступ |
| F2 | API Gateway → Load Balancer | mTLS | Session tokens | Внутренняя сеть |
| F3 | Load Balancer → Auth Service | Internal | Auth requests | Микросервис |
| F4 | Load Balancer → API Service | Internal | API requests | Микросервис |
| F5 | Auth Service → Database | Encrypted | User data, PII | Критичные данные |
| F6 | API Service → Database | Encrypted | Business data | Критичные данные |
| F7 | API Service → Cache | Internal | Session data | Временное хранение |
| F8 | Auth Service → Secret Vault | Secure | Secrets, keys | Управление секретами |
| F9 | API Service → Logging Service | Internal | Logs, metrics | Мониторинг |
| F10 | Logging Service → Database | Encrypted | Audit logs | Аудит |
| F11 | External Services → API Gateway | HTTPS | API calls | Внешние интеграции |

## Границы доверия

### Edge (Граница сети)
- **Компоненты**: API Gateway, Load Balancer
- **Угрозы**: DDoS, Brute force, Injection attacks
- **Контроли**: Rate limiting, WAF, DDoS protection

### Core (Ядро системы)
- **Компоненты**: Auth Service, API Service, Logging Service
- **Угрозы**: Privilege escalation, Data tampering
- **Контроли**: Authentication, Authorization, Input validation

### Data (Граница данных)
- **Компоненты**: Database, Cache, Secret Vault
- **Угрозы**: Data breach, Unauthorized access
- **Контроли**: Encryption, Access controls, Audit logging

## Альтернативный сценарий: Административный доступ

```mermaid
flowchart TD
    ADMIN[👨‍💼 Admin]

    subgraph AdminZone["🔒 Trust Boundary: Admin"]
        ADMIN_GW[🚪 Admin Gateway]
        ADMIN_API[📡 Admin API]
    end

    subgraph Core["🔒 Trust Boundary: Core"]
        AUTH[🔐 Auth Service]
        API[📡 API Service]
    end

    subgraph Data["🔒 Trust Boundary: Data"]
        DB[(🗄️ Database)]
        VAULT[🔑 Secret Vault]
    end

    ADMIN -->|F12: VPN + 2FA| ADMIN_GW
    ADMIN_GW -->|F13: mTLS| ADMIN_API
    ADMIN_API -->|F14: Privileged| AUTH
    ADMIN_API -->|F15: Privileged| API
    ADMIN_API -->|F16: Direct| DB
    ADMIN_API -->|F17: Secure| VAULT

    style AdminZone stroke:#9c27b0,stroke-width:3px
    style ADMIN fill:#f3e5f5
```

## Ключевые потоки для анализа угроз

### Критичные потоки (высокий приоритет)
- **F1**: User → API Gateway (публичный доступ)
- **F5**: Auth Service → Database (PII данные)
- **F8**: Auth Service → Secret Vault (секреты)
- **F10**: Logging Service → Database (аудит)

### Средний приоритет
- **F2**: API Gateway → Load Balancer
- **F6**: API Service → Database
- **F9**: API Service → Logging Service

### Низкий приоритет
- **F7**: API Service → Cache
- **F11**: External Services → API Gateway

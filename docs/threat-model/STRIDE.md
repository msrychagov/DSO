# STRIDE Threat Analysis

## Обзор
Данный документ содержит анализ угроз по методологии STRIDE для SecDev Course Project.

## STRIDE Угрозы и Контроли

| Поток/Элемент | Угроза (STRIDE) | Описание угрозы | Контроль | Ссылка на NFR | Проверка/Артефакт |
|---------------|-----------------|-----------------|----------|---------------|-------------------|
| F1 /login | **S**poofing | Подделка пользователя через перехват credentials | MFA + Rate limiting + Strong authentication | NFR-01, NFR-07 | e2e тесты + ZAP baseline |
| F1 /login | **T**ampering | Модификация запросов аутентификации | Input validation + Request signing | NFR-02 | Contract tests + Security headers |
| F2 API Gateway | **R**epudiation | Отказ от выполнения запросов | Comprehensive logging + Digital signatures | NFR-06 | Audit logs + SIEM monitoring |
| F3 Auth Service | **I**nformation Disclosure | Утечка учетных данных или PII | Encryption in transit/rest + Access controls | NFR-08, NFR-09 | Penetration testing + Data classification |
| F4 API Service | **D**enial of Service | Перегрузка API сервиса | Rate limiting + Resource quotas + Circuit breakers | NFR-03, NFR-07 | Load testing + Monitoring |
| F5 Database | **E**levation of Privilege | Повышение привилегий доступа к БД | Principle of least privilege + RBAC | NFR-01, NFR-06 | Access reviews + Privilege audits |
| F6 Database | **T**ampering | Модификация данных в БД | Database encryption + Integrity checks | NFR-08 | Database auditing + Change tracking |
| F7 Cache | **I**nformation Disclosure | Утечка кэшированных данных | Cache encryption + TTL policies | NFR-09 | Cache security testing |
| F8 Secret Vault | **S**poofing | Подделка доступа к секретам | Strong authentication + Certificate-based access | NFR-05 | Secret rotation testing |
| F9 Logging Service | **R**epudiation | Манипуляции с логами безопасности | Immutable logs + Digital signatures | NFR-06 | Log integrity verification |
| F10 Database | **T**ampering | Модификация аудит логов | Immutable storage + Write-only access | NFR-06 | Log tampering detection |
| F11 External Services | **D**enial of Service | DDoS атаки на внешние интеграции | DDoS protection + Circuit breakers | NFR-03, NFR-07 | DDoS testing + Traffic analysis |
| API Gateway | **E**levation of Privilege | Обход авторизации через API Gateway | Proper authorization checks + Token validation | NFR-01, NFR-09 | Authorization testing |
| Auth Service | **I**nformation Disclosure | Утечка токенов и сессий | Secure token storage + Session management | NFR-09 | Token security testing |
| Database | **S**poofing | Подделка подключений к БД | Certificate-based authentication + Network isolation | NFR-08 | Database connection testing |

## Детальный анализ по категориям STRIDE

### S - Spoofing (Подделка)
**Критичные угрозы:**
- Подделка пользователей через перехват credentials (F1)
- Подделка доступа к секретам (F8)
- Подделка подключений к БД

**Контроли:**
- MFA для пользователей
- Certificate-based authentication
- Strong password policies (NFR-01)

### T - Tampering (Модификация)
**Критичные угрозы:**
- Модификация запросов аутентификации (F1)
- Модификация данных в БД (F6)
- Модификация аудит логов (F10)

**Контроли:**
- Input validation (NFR-02)
- Database encryption
- Immutable logs (NFR-06)

### R - Repudiation (Отказ)
**Критичные угрозы:**
- Отказ от выполнения запросов (F2)
- Манипуляции с логами безопасности (F9)

**Контроли:**
- Comprehensive logging (NFR-06)
- Digital signatures
- Audit trails

### I - Information Disclosure (Раскрытие информации)
**Критичные угрозы:**
- Утечка учетных данных или PII (F3)
- Утечка кэшированных данных (F7)
- Утечка токенов и сессий

**Контроли:**
- Encryption in transit/rest (NFR-08)
- Access controls
- Secure token storage (NFR-09)

### D - Denial of Service (Отказ в обслуживании)
**Критичные угрозы:**
- Перегрузка API сервиса (F4)
- DDoS атаки на внешние интеграции (F11)

**Контроли:**
- Rate limiting (NFR-07)
- Resource quotas
- DDoS protection (NFR-03)

### E - Elevation of Privilege (Повышение привилегий)
**Критичные угрозы:**
- Повышение привилегий доступа к БД (F5)
- Обход авторизации через API Gateway

**Контроли:**
- Principle of least privilege
- RBAC (Role-Based Access Control)
- Proper authorization checks (NFR-01)

## Связь с NFR из P03

| NFR ID | STRIDE Угрозы | Контроли |
|--------|---------------|----------|
| NFR-01 | S, E | Argon2id хэширование, RBAC |
| NFR-02 | T | RFC7807 формат ошибок |
| NFR-03 | D | Производительность, DDoS защита |
| NFR-04 | Все | Уязвимости зависимостей |
| NFR-05 | S | Ротация секретов |
| NFR-06 | R, T | Логирование безопасности |
| NFR-07 | S, D | Rate limiting |
| NFR-08 | I, T | HTTPS/TLS |
| NFR-09 | I, S | Время жизни токенов |
| NFR-10 | Все | Мониторинг аномалий |

## Приоритизация угроз

### Высокий приоритет (Критичные)
1. **F1 Spoofing** - Подделка пользователей
2. **F5 Elevation of Privilege** - Повышение привилегий БД
3. **F3 Information Disclosure** - Утечка PII
4. **F6 Tampering** - Модификация данных БД

### Средний приоритет (Важные)
5. **F4 Denial of Service** - Перегрузка API
6. **F8 Spoofing** - Подделка доступа к секретам
7. **F9 Repudiation** - Манипуляции с логами
8. **F11 Denial of Service** - DDoS атаки

### Низкий приоритет (Средние)
9. **F7 Information Disclosure** - Утечка кэша
10. **F2 Repudiation** - Отказ от запросов
11. **F10 Tampering** - Модификация аудит логов

## Рекомендации по тестированию

### Автоматизированное тестирование
- **ZAP Baseline** для F1, F2
- **Contract tests** для F1, F2
- **Load testing** для F4, F11
- **Penetration testing** для F3, F5

### Ручное тестирование
- **Authorization testing** для F5, API Gateway
- **Token security testing** для Auth Service
- **Database connection testing** для Database
- **Log integrity verification** для F9, F10

### Мониторинг в production
- **SIEM monitoring** для R угроз
- **Traffic analysis** для D угроз
- **Access reviews** для E угроз
- **Data classification** для I угроз

#!/usr/bin/env python3
"""
Скрипт для проверки выполнения Security NFR
"""

import json
import subprocess
import sys
import time
from typing import Any, Dict

import requests


class NFRChecker:
    """Класс для проверки выполнения Security NFR"""

    def __init__(self):
        self.results = {}
        self.base_url = "http://localhost:8000"

    def check_nfr_02_error_format(self) -> Dict[str, Any]:
        """NFR-02: Проверка формата ошибок RFC7807"""
        try:
            # Тестируем несуществующий endpoint
            response = requests.get(f"{self.base_url}/items/999", timeout=5)

            result = {
                "nfr_id": "NFR-02",
                "name": "Ошибки в формате RFC7807",
                "status": "PASS" if response.status_code == 404 else "FAIL",
                "details": {
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "has_correlation_id": "correlation_id" in response.text.lower(),
                },
            }

            # Проверяем наличие correlation_id в ответе
            if "correlation_id" in response.text.lower():
                result["status"] = "PASS"
            else:
                result["status"] = "FAIL"
                result["details"]["missing_correlation_id"] = True

        except Exception as e:
            result = {
                "nfr_id": "NFR-02",
                "name": "Ошибки в формате RFC7807",
                "status": "ERROR",
                "details": {"error": str(e)},
            }

        return result

    def check_nfr_07_rate_limiting(self) -> Dict[str, Any]:
        """NFR-07: Проверка Rate Limiting"""
        try:
            # Делаем несколько запросов подряд
            responses = []
            for i in range(6):
                response = requests.get(f"{self.base_url}/health", timeout=5)
                responses.append(response.status_code)
                time.sleep(0.1)  # Небольшая задержка между запросами

            # Проверяем, есть ли блокировка (код 429)
            has_rate_limiting = 429 in responses

            result = {
                "nfr_id": "NFR-07",
                "name": "Rate Limiting",
                "status": "PASS" if has_rate_limiting else "FAIL",
                "details": {"response_codes": responses, "has_429": has_rate_limiting},
            }

        except Exception as e:
            result = {
                "nfr_id": "NFR-07",
                "name": "Rate Limiting",
                "status": "ERROR",
                "details": {"error": str(e)},
            }

        return result

    def check_nfr_03_performance(self) -> Dict[str, Any]:
        """NFR-03: Проверка производительности"""
        try:
            start_time = time.time()
            response = requests.get(f"{self.base_url}/health", timeout=5)
            end_time = time.time()

            response_time = (end_time - start_time) * 1000  # в миллисекундах

            # Проверяем, что время ответа меньше 300ms
            is_performant = response_time < 300

            result = {
                "nfr_id": "NFR-03",
                "name": "Производительность",
                "status": "PASS" if is_performant else "FAIL",
                "details": {
                    "response_time_ms": round(response_time, 2),
                    "threshold_ms": 300,
                    "status_code": response.status_code,
                },
            }

        except Exception as e:
            result = {
                "nfr_id": "NFR-03",
                "name": "Производительность",
                "status": "ERROR",
                "details": {"error": str(e)},
            }

        return result

    def check_nfr_04_dependencies(self) -> Dict[str, Any]:
        """NFR-04: Проверка уязвимостей зависимостей"""
        try:
            # Запускаем safety check для Python зависимостей
            result = subprocess.run(
                ["python", "-m", "safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            vulnerabilities = []
            if result.returncode == 0:
                # Нет уязвимостей
                status = "PASS"
            else:
                # Есть уязвимости
                try:
                    vuln_data = json.loads(result.stdout)
                    vulnerabilities = vuln_data.get("vulnerabilities", [])
                    status = "FAIL" if vulnerabilities else "PASS"
                except json.JSONDecodeError:
                    status = "ERROR"

            result_data = {
                "nfr_id": "NFR-04",
                "name": "Уязвимости зависимостей",
                "status": status,
                "details": {
                    "vulnerabilities_count": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities[:5],  # Первые 5 для краткости
                    "safety_exit_code": result.returncode,
                },
            }

        except subprocess.TimeoutExpired:
            result_data = {
                "nfr_id": "NFR-04",
                "name": "Уязвимости зависимостей",
                "status": "ERROR",
                "details": {"error": "Safety check timeout"},
            }
        except Exception as e:
            result_data = {
                "nfr_id": "NFR-04",
                "name": "Уязвимости зависимостей",
                "status": "ERROR",
                "details": {"error": str(e)},
            }

        return result_data

    def run_all_checks(self) -> Dict[str, Any]:
        """Запуск всех проверок NFR"""
        print("🔍 Запуск проверки Security NFR...")

        checks = [
            self.check_nfr_02_error_format,
            self.check_nfr_07_rate_limiting,
            self.check_nfr_03_performance,
            self.check_nfr_04_dependencies,
        ]

        results = []
        for check in checks:
            try:
                result = check()
                results.append(result)
                if result["status"] == "PASS":
                    status_emoji = "✅"
                elif result["status"] == "FAIL":
                    status_emoji = "❌"
                else:
                    status_emoji = "⚠️"
                print(
                    f"{status_emoji} {result['nfr_id']}: {result['name']} - {result['status']}"
                )
            except Exception as e:
                print(f"❌ Ошибка при выполнении проверки: {e}")

        # Подсчет статистики
        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = sum(1 for r in results if r["status"] == "FAIL")
        errors = sum(1 for r in results if r["status"] == "ERROR")

        summary = {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "success_rate": round((passed / total) * 100, 2) if total > 0 else 0,
            "results": results,
        }

        print("\n📊 Результаты проверки NFR:")
        print(f"   Всего проверок: {total}")
        print(f"   ✅ Прошло: {passed}")
        print(f"   ❌ Не прошло: {failed}")
        print(f"   ⚠️ Ошибки: {errors}")
        print(f"   📈 Успешность: {summary['success_rate']}%")

        return summary


def main():
    """Главная функция"""
    checker = NFRChecker()
    results = checker.run_all_checks()

    # Сохраняем результаты в файл
    with open("nfr_check_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("\n💾 Результаты сохранены в nfr_check_results.json")

    # Возвращаем код выхода в зависимости от результатов
    if results["failed"] > 0 or results["errors"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

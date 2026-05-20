"""
PII Guard — алгоритмическая валидация находок по контрольным суммам.
Используется после RegEx-сканирования для снижения ложных срабатываний.
"""
import re


def _digits(s: str) -> str:
    """Оставляет только цифры."""
    return re.sub(r'\D', '', s)


def luhn_check(s: str) -> bool:
    """Алгоритм Луна — проверка номеров банковских карт."""
    digits = _digits(s)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def inn10_check(s: str) -> bool:
    """Контрольная цифра ИНН юридического лица (10 цифр)."""
    digits = _digits(s)
    if len(digits) != 10:
        return False
    weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    check = sum(weights[i] * int(digits[i]) for i in range(9)) % 11 % 10
    return check == int(digits[9])


def inn12_check(s: str) -> bool:
    """Контрольные цифры ИНН физического лица (12 цифр)."""
    digits = _digits(s)
    if len(digits) != 12:
        return False
    w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    c1 = sum(w1[i] * int(digits[i]) for i in range(10)) % 11 % 10
    c2 = sum(w2[i] * int(digits[i]) for i in range(11)) % 11 % 10
    return c1 == int(digits[10]) and c2 == int(digits[11])


def snils_check(s: str) -> bool:
    """
    Контрольные цифры СНИЛС (11 цифр, формат NNN-NNN-NNN CC).
    Номера до 001-001-998 считаются действительными без проверки суммы.
    """
    digits = _digits(s)
    if len(digits) != 11:
        return False
    number = int(digits[:9])
    if number < 1001998:
        return True  # старые номера без контрольной суммы
    total = sum((9 - i) * int(digits[i]) for i in range(9)) % 101
    if total >= 100:
        total = 0
    return total == int(digits[9:11])


def validate(pii_type: str, value: str):
    """
    Запускает алгоритмическую проверку для типа PII.

    Возвращает:
      True  — значение прошло алгоритм
      False — значение не прошло алгоритм (вероятно ложное срабатывание)
      None  — алгоритма для этого типа нет (только RegEx)
    """
    t = pii_type.lower()
    if 'credit card' in t:
        return luhn_check(value)
    if 'inn (company' in t:
        return inn10_check(value)
    if 'inn (individual' in t:
        return inn12_check(value)
    if 'snils' in t:
        return snils_check(value)
    return None

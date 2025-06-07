import secrets
import os
import base64
from typing import Tuple, Optional
import gostcrypto.gosthash

"""
Параметры эллиптической кривой для ГОСТ Р 34.10-2012 (256-бит)
"""
p = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
b = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
G = (
    int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
    int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
)
q = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

def mod_inverse(a: int, m: int) -> int:
    """
    Вычисляет модульный обратный элемент a⁻¹ mod m с использованием расширенного алгоритма Евклида.
    
    Параметры:
        a (int): Число, для которого ищем обратное
        m (int): Модуль
    
    Возвращает:
        int: Модульный обратный элемент
    
    Исключения:
        ValueError: Если обратный элемент не существует (gcd(a, m) ≠ 1)
    """
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Рекурсивная реализация расширенного алгоритма Евклида."""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Модульный обратный элемент не существует")
    return (x % m + m) % m

def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """
    Выполняет сложение двух точек на эллиптической кривой.
    
    Параметры:
        P (Tuple[int, int] | None): Первая точка (x, y) или None (бесконечность)
        Q (Tuple[int, int] | None): Вторая точка (x, y) или None (бесконечность)
    
    Возвращает:
        Tuple[int, int] | None: Результат сложения или None (бесконечность)
    
    Особые случаи:
        - Если любая точка None, возвращает другую точку
        - Если точки противоположны (P + (-P)), возвращает None (бесконечность)
    """
    if P is None:
        return Q
    if Q is None:
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    # Проверка на противоположные точки (P + (-P) = бесконечность)
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    # Удвоение точки (P + P)
    if P == Q:
        # Вертикальная касательная
        if y1 == 0:
            return None
        # Вычисление углового коэффициента для удвоения
        lam = ((3 * x1 * x1 + a) * mod_inverse(2 * y1, p)) % p
    # Сложение разных точек
    else:
        # Вычисление углового коэффициента
        lam = ((y2 - y1) * mod_inverse((x2 - x1) % p, p)) % p
    
    # Вычисление координат результирующей точки
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mult(k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    """
    Умножает точку на скаляр (операция k*P) с использованием метода double-and-add.
    
    Параметры:
        k (int): Скаляр-множитель
        P (Tuple[int, int]): Точка на кривой
    
    Возвращает:
        Tuple[int, int] | None: Результат умножения или None (бесконечность)
    """
    result = None  # Начальное значение - точка на бесконечности
    temp = P
    # Приведение скаляра по модулю порядка группы
    k = k % q
    
    # Алгоритм double-and-add
    while k > 0:
        # Если младший бит k установлен, добавляем текущую точку
        if k & 1:
            result = point_add(result, temp)
        # Удваиваем текущую точку
        temp = point_add(temp, temp)
        # Сдвигаем k вправо
        k >>= 1
    
    return result

def is_on_curve(x: int, y: int) -> bool:
    """
    Проверяет, принадлежит ли точка (x, y) эллиптической кривой.
    
    Параметры:
        x (int): x-координата точки
        y (int): y-координата точки
    
    Возвращает:
        bool: True если точка на кривой, иначе False
    
    Проверка: y² ≡ x³ + ax + b (mod p)
    """
    left = (y * y) % p
    right = (x*x*x + a*x + b) % p
    return left == right

def write_pem(filename: str, data: bytes, key_type: str) -> None:
    """
    Записывает данные в файл в формате PEM.

    Формат PEM:
        -----BEGIN {key_type}-----
        Base64-кодированные данные
        -----END {key_type}-----
    """
    b64 = base64.b64encode(data).decode('ascii')  # Кодирование в Base64
    with open(filename, 'w') as f:
        f.write(f"-----BEGIN {key_type}-----\n")
        f.write(b64 + '\n')
        f.write(f"-----END {key_type}-----\n")

def read_pem(filename: str, key_type: str) -> bytes:
    """
    Читает данные из PEM-файла.
    
    Параметры:
        filename (str): Имя файла для чтения
        key_type (str): Ожидаемый тип ключа (для проверки заголовков)
    
    Возвращает:
        bytes: Декодированные двоичные данные
    
    Исключения:
        ValueError: При ошибках чтения или несоответствии формата
    """
    try:
        with open(filename, 'r') as f:
            data = f.read()
        
        # Определение шаблонов заголовков
        begin = f"-----BEGIN {key_type}-----"
        end = f"-----END {key_type}-----"
        
        # Извлечение Base64-данных между заголовками
        b64_data = data.split(begin)[1].split(end)[0].strip()
        # Декодирование Base64
        return base64.b64decode(b64_data)
    except Exception as e:
        raise ValueError(f"Ошибка чтения PEM файла: {e}")

def generate_keypair() -> None:
    """
    Генерирует пару ключей (закрытый и открытый) и сохраняет их в файлы.
    
    Процесс:
      1. Генерирует случайное число d (закрытый ключ) в диапазоне [1, q-1]
      2. Вычисляет открытый ключ Q = d*G
      3. Проверяет, что базовая точка G и полученная точка Q лежат на кривой
      4. Сохраняет закрытый ключ в private_key.pem
      5. Сохраняет открытый ключ в public_key.pem
    
    Исключения:
        ValueError: При ошибках генерации или проверки точек
    """
    # Генерация случайного закрытого ключа
    d = secrets.randbelow(q - 1) + 1
    # Вычисление открытого ключа
    Q = point_mult(d, G)
    
    if Q is None:
        raise ValueError("Не удалось сгенерировать открытый ключ")
    
    # Проверка базовой точки
    if not is_on_curve(G[0], G[1]):
        raise RuntimeError("Базовая точка G не на кривой!")
    
    # Проверка сгенерированной точки
    if not is_on_curve(Q[0], Q[1]):
        raise RuntimeError("Сгенерированная точка Q не на кривой!")
    
    # Сохранение ключей в PEM-формате
    write_pem('private_key.pem', d.to_bytes(32, 'big'), 'GOST PRIVATE KEY')
    write_pem('public_key.pem', Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big'), 'GOST PUBLIC KEY')
    print("Ключи сгенерированы: private_key.pem, public_key.pem")

def sign_file(file_path: str) -> None:
    """
    Создает ЭЦП для указанного файла и сохраняет ее в signature.sig.
    
    Процесс:
      1. Читает закрытый ключ из private_key.pem
      2. Вычисляет хеш файла по алгоритму Стрибог 256
      3. Генерирует подпись (r, s) по ГОСТ Р 34.10-2012
      4. Сохраняет подпись в формате "r,s" в signature.sig
    
    Параметры:
        file_path (str): Путь к файлу для подписи
    
    Особенности:
        - Повторяет попытки при получении некорректных r или s
    """
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден")
        return
    
    try:
        # Чтение закрытого ключа
        data = read_pem('private_key.pem', 'GOST PRIVATE KEY')
        if len(data) != 32:
            raise ValueError("Некорректная длина закрытого ключа")
        d = int.from_bytes(data, 'big')
    except Exception as e:
        print(f"Ошибка чтения закрытого ключа: {e}")
        return

    # Вычисление хеша файла (Стрибог 256)
    hasher = gostcrypto.gosthash.new('streebog256')
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    # Приведение хеша к числу по модулю q
    h = int.from_bytes(hasher.digest(), 'big') % q

    # Генерация подписи
    while True:
        # Генерация случайного секретного параметра k
        k = secrets.randbelow(q - 1) + 1
        # Вычисление точки R = k*G
        R = point_mult(k, G)
        if R is None:
            continue
        r = R[0] % q
        if r == 0:
            continue
        try:
            # Вычисление s = (k⁻¹ * (h + d*r)) mod q
            k_inv = mod_inverse(k, q)
            s = (k_inv * (h + d * r)) % q
        except ValueError:  # Если k не обратимо (кратно q)
            continue
        if s != 0:
            break

    # Сохранение подписи
    with open('signature.sig', 'w') as f:
        f.write(f"{r},{s}")
    print("Подпись создана: signature.sig")

def verify_file(file_path: str) -> None:
    """
    Проверяет ЭЦП для указанного файла.
    
    Процесс:
      1. Читает открытый ключ из public_key.pem
      2. Читает подпись из signature.sig
      3. Проверяет принадлежность открытого ключа кривой
      4. Вычисляет хеш файла
      5. Проверяет подпись по алгоритму ГОСТ Р 34.10-2012
    
    Параметры:
        file_path (str): Путь к файлу для проверки
    
    Результат:
        Выводит "Подпись верна" или причину ошибки
    """
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден")
        return
    
    try:
        # Чтение открытого ключа
        data = read_pem('public_key.pem', 'GOST PUBLIC KEY')
        if len(data) != 64:
            raise ValueError("Некорректная длина открытого ключа (ожидается 64 байта)")
        x = int.from_bytes(data[:32], 'big')
        y = int.from_bytes(data[32:], 'big')
        
        # Проверка принадлежности точки кривой
        if not is_on_curve(x, y):
            print("Открытый ключ не принадлежит кривой")
            return

        # Чтение подписи
        with open('signature.sig', 'r') as f:
            parts = f.read().strip().split(',')
            if len(parts) != 2:
                raise ValueError("Некорректный формат подписи (ожидается r,s)")
            r, s = map(int, parts)
    except Exception as e:
        print(f"Ошибка чтения данных: {e}")
        return

    # Проверка диапазонов r и s
    if not (1 <= r < q and 1 <= s < q):
        print("Подпись неверна (r или s вне диапазона [1, q-1])")
        return

    # Вычисление хеша файла
    hasher = gostcrypto.gosthash.new('streebog256')
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    h = int.from_bytes(hasher.digest(), 'big') % q

    try:
        # Вычисление промежуточных параметров
        w = mod_inverse(s, q)
    except ValueError:
        print("Подпись неверна (ошибка вычисления модульного обратного для s)")
        return

    u1 = (h * w) % q
    u2 = (r * w) % q

    # Вычисление R' = u1*G + u2*Q
    P1 = point_mult(u1, G)
    P2 = point_mult(u2, (x, y))
    R = point_add(P1, P2)

    # Проверка подписи
    if R is None:
        print("Подпись неверна (результирующая точка на бесконечности)")
        return
        
    # Проверка: x-координата R' должна равняться r mod q
    if (R[0] % q) != r:
        print("Подпись неверна (r не совпадает)")
    else:
        print("Подпись верна")

def main():
    """
    Главная функция программы - предоставляет пользовательский интерфейс.
    
    Функционал:
      - Проверяет базовую точку при запуске
      - Предлагает команды: generate, sign, verify, exit
      - Обрабатывает ошибки выполнения команд
    """
    # Критическая проверка точки
    if not is_on_curve(G[0], G[1]):
        print("ОШИБКА: Базовая точка G не принадлежит кривой!")
        return
    
    # Пользовательский интерфейс
    print("=== Программа ЭЦП по ГОСТ Р 34.10-2012 ===")
    print("[1] generate - Сгенерировать ключевую пару")
    print("[2] sign - Подписать файл")
    print("[3] verify - Проверить подпись")
    print("[4] exit - Выйти")

    while True:
        command = input("Введите команду (generate/sign/verify/exit): ").strip().lower()
        
        if command == 'exit':
            print("Программа завершена")
            break
        elif command == 'generate':
            try:
                generate_keypair()
            except Exception as e:
                print(f"Ошибка генерации ключей: {e}")
        elif command == 'sign':
            file_path = input("Введите путь к файлу для подписи: ").strip()
            sign_file(file_path)
        elif command == 'verify':
            file_path = input("Введите путь к файлу для проверки: ").strip()
            verify_file(file_path)
        else:
            print("Неизвестная команда. Доступные команды: generate, sign, verify, exit")

if __name__ == "__main__":
    main()
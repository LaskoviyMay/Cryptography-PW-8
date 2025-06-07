import secrets
import os
from typing import Tuple
import gostcrypto.gosthash

# Параметры эллиптической кривой из ГОСТ Р 34.10-2012 (для длины 256 бит)
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16)
a = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16)
b = int("A6", 16)
G = (
    int("1", 16),
    int("8D91E471E0980C1F5D1F4D8C5B6A8B6F7E7E3D9E0B6E6B6E7E3D9E0B6E6B6E7", 16)
)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16)

def mod_inverse(a: int, m: int) -> int:
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
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

def point_add(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # точка на бесконечности
    if P == Q:
        if y1 == 0:
            return None
        lam = ((3 * x1 * x1 + a) * mod_inverse(2 * y1, p)) % p
    else:
        lam = ((y2 - y1) * mod_inverse((x2 - x1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mult(k: int, P: Tuple[int, int]) -> Tuple[int, int]:
    result = None  # Начальное значение — точка на бесконечности
    temp = P
    k = k % q
    while k > 0:
        if k & 1:
            result = point_add(result, temp)
        temp = point_add(temp, temp)
        k >>= 1
    return result

def generate_keypair() -> None:
    d = secrets.randbelow(q - 1) + 1
    Q = point_mult(d, G)
    if Q is None:
        raise ValueError("Не удалось сгенерировать открытый ключ")
    with open('private_key.txt', 'w') as f:
        f.write(str(d))
    with open('public_key.txt', 'w') as f:
        f.write(f"{Q[0]},{Q[1]}")
    print("Ключи сгенерированы: private_key.txt, public_key.txt")

def sign_file(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден")
        return
    try:
        with open('private_key.txt', 'r') as f:
            d = int(f.read().strip())
    except (FileNotFoundError, ValueError) as e:
        print(f"Ошибка чтения закрытого ключа: {e}")
        return

    hasher = gostcrypto.gosthash.new('streebog256')
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    h = int.from_bytes(hasher.digest(), 'big') % q

    while True:
        k = secrets.randbelow(q - 1) + 1
        R = point_mult(k, G)
        if R is None:
            continue
        r = R[0] % q
        if r == 0:
            continue
        s = (mod_inverse(k, q) * (h + d * r)) % q
        if s != 0:
            break

    with open('signature.txt', 'w') as f:
        f.write(f"{r},{s}")
    print("Подпись создана: signature.txt")

def verify_file(file_path: str) -> None:
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не найден")
        return
    if not os.path.exists('public_key.txt'):
        print("Файл public_key.txt не найден")
        return
    if not os.path.exists('signature.txt'):
        print("Файл signature.txt не найден")
        return

    try:
        with open('public_key.txt', 'r') as f:
            x, y = map(int, f.read().strip().split(','))
        with open('signature.txt', 'r') as f:
            r, s = map(int, f.read().strip().split(','))
    except (ValueError, FileNotFoundError) as e:
        print(f"Ошибка чтения данных: {e}")
        return

    if not (1 <= r < q and 1 <= s < q):
        print("Подпись неверна (r или s вне диапазона)")
        return

    hasher = gostcrypto.gosthash.new('streebog256')
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    h = int.from_bytes(hasher.digest(), 'big') % q

    try:
        w = mod_inverse(s, q)
    except ValueError:
        print("Подпись неверна (ошибка в модульном обратном элементе)")
        return

    u1 = (h * w) % q
    u2 = (r * w) % q

    P1 = point_mult(u1, G)
    P2 = point_mult(u2, (x, y))
    R = point_add(P1, P2)

    if R is None or (R[0] % q) != r:
        print("Подпись неверна")
    else:
        print("Подпись верна")

def main():
    print("=== Программа ЭЦП по ГОСТ Р 34.10-2012 ===")
    print("1. generate - Сгенерировать ключевую пару")
    print("2. sign - Подписать файл")
    print("3. verify - Проверить подпись")
    print("4. exit - Выйти")

    while True:
        command = input("Введите команду (generate/sign/verify/exit): ").strip().lower()
        if command == 'exit':
            print("Программа завершена")
            break
        elif command == 'generate':
            generate_keypair()
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
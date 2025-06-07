import secrets
import argparse
import os
from typing import Tuple
import gostcrypto.gosthash

# Параметры эллиптической кривой ГОСТ Р 34.10-2012 (id-tc26-gost-3410-12-512-paramSetA)
p = 57896044618658097711785492504343953926634992332820282019728792003956564823193
a = 7
b = 43308876546767276905765904595650931995942111794451039587316730224963703718511
G = (2, 4018974056539037503335449422937059775635739389905545080690979365213431566280)
q = 57896044618658097711785492504343953926634992332820282019728792003956564823193

def mod_inverse(a: int, m: int) -> int:
    """Вычисление обратного элемента по модулю."""
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
    """Сложение двух точек на эллиптической кривой."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 == (-y2 % p):
        return None
    if x1 == x2 and y1 == y2:
        # Удвоение точки
        if y1 == 0:
            return None
        lam = ((3 * x1 * x1 + a) * mod_inverse(2 * y1, p)) % p
    else:
        # Сложение разных точек
        if x1 == x2:
            return None
        lam = ((y2 - y1) * mod_inverse((x2 - x1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mult(k: int, P: Tuple[int, int]) -> Tuple[int, int]:
    """Умножение точки на скаляр."""
    if k == 0 or P is None:
        return None
    result = None
    temp = P
    k = k % q
    while k > 0:
        if k & 1:
            result = point_add(result, temp)
        temp = point_add(temp, temp)
        k >>= 1
    return result

def generate_keypair() -> Tuple[int, Tuple[int, int]]:
    """Генерация ключевой пары: закрытый ключ d и открытый ключ Q."""
    d = secrets.randbelow(q - 1) + 1  # Закрытый ключ
    Q = point_mult(d, G)  # Открытый ключ Q = d * G
    if Q is None:
        raise ValueError("Не удалось сгенерировать открытый ключ")
    return d, Q

def sign_file(file_path: str, private_key: int) -> Tuple[int, int]:
    """Создание ЭЦП для файла с использованием ГОСТ Р 34.11-2012."""
    # Хэширование файла с помощью Стрибог-256
    hasher = gostcrypto.gosthash.new('streebog256')
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл {file_path} не найден")
    h = int.from_bytes(hasher.digest(), 'big') % q

    # Генерация подписи (r, s)
    while True:
        k = secrets.randbelow(q - 1) + 1  # Случайное k
        R = point_mult(k, G)
        if R is None:
            continue
        r = R[0] % q
        if r == 0:
            continue
        s = (mod_inverse(k, q) * (h + private_key * r)) % q
        if s != 0:
            break
    return (r, s)

def verify_file(file_path: str, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
    """Проверка ЭЦП файла с использованием ГОСТ Р 34.11-2012."""
    r, s = signature
    if not (1 <= r < q and 1 <= s < q):
        return False

    # Хэширование файла с помощью Стрибог-256
    hasher = gostcrypto.gosthash.new('streebog256')
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл {file_path} не найден")
    h = int.from_bytes(hasher.digest(), 'big') % q

    # Проверка подписи
    try:
        w = mod_inverse(s, q)
    except ValueError:
        return False
    u1 = (h * w) % q
    u2 = (r * w) % q
    P1 = point_mult(u1, G)
    P2 = point_mult(u2, public_key)
    R = point_add(P1, P2)
    if R is None:
        return False
    return (R[0] % q) == r

def main():
    parser = argparse.ArgumentParser(description="ЭЦП по ГОСТ Р 34.10-2012 с хэшированием ГОСТ Р 34.11-2012")
    parser.add_argument('--generate-keys', action='store_true', help="Генерировать ключевую пару")
    parser.add_argument('--sign', type=str, help="Файл для подписи")
    parser.add_argument('--verify', type=str, help="Файл для проверки подписи")
    parser.add_argument('--private-key', type=str, help="Файл с закрытым ключом")
    parser.add_argument('--public-key', type=str, help="Файл с открытым ключом")
    parser.add_argument('--signature', type=str, help="Файл с подписью")
    args = parser.parse_args()

    try:
        # Если аргументы командной строки предоставлены, используем их
        if args.generate_keys or args.sign or args.verify:
            if args.generate_keys:
                d, Q = generate_keypair()
                with open('private_key.txt', 'w') as f:
                    f.write(str(d))
                with open('public_key.txt', 'w') as f:
                    f.write(f"{Q[0]},{Q[1]}")
                print("Ключи сгенерированы: private_key.txt, public_key.txt")
                return

            if args.sign and args.private_key:
                if not os.path.exists(args.sign):
                    print(f"Файл {args.sign} не существует")
                    return
                try:
                    with open(args.private_key, 'r') as f:
                        d = int(f.read().strip())
                except (FileNotFoundError, ValueError) as e:
                    print(f"Ошибка чтения закрытого ключа: {e}")
                    return
                r, s = sign_file(args.sign, d)
                with open('signature.txt', 'w') as f:
                    f.write(f"{r},{s}")
                print("Подпись создана: signature.txt")
                return

            if args.verify and args.signature and args.public_key:
                if not os.path.exists(args.verify):
                    print(f"Файл {args.verify} не существует")
                    return
                try:
                    with open(args.signature, 'r') as f:
                        r, s = map(int, f.read().strip().split(','))
                    with open(args.public_key, 'r') as f:
                        x, y = map(int, f.read().strip().split(','))
                except (FileNotFoundError, ValueError) as e:
                    print(f"Ошибка чтения подписи или открытого ключа: {e}")
                    return
                if verify_file(args.verify, (r, s), (x, y)):
                    print("Подпись верна")
                else:
                    print("Подпись неверна")
                return

        # Интерактивный режим, если аргументы не предоставлены
        print("Добро пожаловать в программу ЭЦП по ГОСТ Р 34.10-2012!")
        print("Доступные команды:")
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
                d, Q = generate_keypair()
                with open('private_key.txt', 'w') as f:
                    f.write(str(d))
                with open('public_key.txt', 'w') as f:
                    f.write(f"{Q[0]},{Q[1]}")
                print("Ключи сгенерированы: private_key.txt, public_key.txt")
            elif command == 'sign':
                file_path = input("Введите путь к файлу для подписи: ").strip()
                private_key_file = input("Введите путь к файлу с закрытым ключом: ").strip()
                if not os.path.exists(file_path):
                    print(f"Файл {file_path} не существует")
                    continue
                try:
                    with open(private_key_file, 'r') as f:
                        d = int(f.read().strip())
                except (FileNotFoundError, ValueError) as e:
                    print(f"Ошибка чтения закрытого ключа: {e}")
                    continue
                r, s = sign_file(file_path, d)
                with open('signature.txt', 'w') as f:
                    f.write(f"{r},{s}")
                print("Подпись создана: signature.txt")
            elif command == 'verify':
                file_path = input("Введите путь к файлу для проверки: ").strip()
                signature_file = input("Введите путь к файлу с подписью: ").strip()
                public_key_file = input("Введите путь к файлу с открытым ключом: ").strip()
                if not os.path.exists(file_path):
                    print(f"Файл {file_path} не существует")
                    continue
                try:
                    with open(signature_file, 'r') as f:
                        r, s = map(int, f.read().strip().split(','))
                    with open(public_key_file, 'r') as f:
                        x, y = map(int, f.read().strip().split(','))
                except (FileNotFoundError, ValueError) as e:
                    print(f"Ошибка чтения подписи или открытого ключа: {e}")
                    continue
                if verify_file(file_path, (r, s), (x, y)):
                    print("Подпись верна")
                else:
                    print("Подпись неверна")
            else:
                print("Неизвестная команда. Доступные команды: generate, sign, verify, exit")

    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()
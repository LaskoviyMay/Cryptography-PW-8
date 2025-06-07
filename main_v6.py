import random
import sys
import argparse
from gostcrypto.gosthash import new as gost_hash

# Параметры кривой из ГОСТ Р 34.10-2012
p = 57896044618658097711785492504343953926418782139537452191302581570759080747169
a = 7
b = 43308876546767276905765900574683423135711535271985780914745867236231519206471
xG = 2
yG = 57896044618658097711785492504343953926418782139537452191302581570759080747168
n = 57896044618658097711785492504343953927082934583725450622380973592137631069619

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def inverse_mod(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def add_points(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x_p, y_p = P
    x_q, y_q = Q

    # Приводим координаты к полю GF(p)
    x_p = x_p % p
    y_p = y_p % p
    x_q = x_q % p
    y_q = y_q % p

    if x_p == x_q and y_p != y_q:
        return None  # Вертикальная линия — результат — нейтральный элемент
    if x_p == x_q and y_p == y_q:
        return double_point(P)  # Удвоение точки

    # Вычисляем коэффициент наклона
    inv = inverse_mod(x_q - x_p, p)
    if inv is None:
        return None  # Невозможно вычислить обратный элемент
    lam = (y_q - y_p) * inv % p

    # Вычисляем координаты новой точки
    x_r = (lam * lam - x_p - x_q) % p
    y_r = (lam * (x_p - x_r) - y_p) % p

    return (x_r, y_r)


def double_point(P):
    x, y = P
    x = x % p
    y = y % p

    if y == 0:
        return None  # Вертикальная линия — результат — нейтральный элемент

    # Вычисляем коэффициент наклона
    inv = inverse_mod(2 * y, p)
    if inv is None:
        return None  # Невозможно вычислить обратный элемент
    lam = (3 * x * x + a) * inv % p

    # Вычисляем координаты новой точки
    x_r = (lam * lam - 2 * x) % p
    y_r = (lam * (x - x_r) - y) % p

    return (x_r, y_r)

def multiply_point(P, k):
    result = None
    addend = P
    while k:
        if k % 2 == 1:
            result = add_points(result, addend)
        addend = double_point(addend)
        k //= 2
    return result

def hash_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    hasher = gost_hash('stribog256')
    hasher.update(data)
    hash_bytes = hasher.digest()
    e = int.from_bytes(hash_bytes, byteorder='big')
    return e % n

def generate_keys():
    while True:
        d = random.randint(1, n-1)
        Q = multiply_point((xG, yG), d)
        if Q is not None:
            return d, Q

def sign_file(file_path, d):
    e = hash_file(file_path)
    while True:
        k = random.randint(1, n-1)
        R = multiply_point((xG, yG), k)
        r = R[0] % n
        if r == 0:
            continue
        s = (d * r + k * e) % n
        if s == 0:
            continue
        return (r, s)

def verify_signature(file_path, Q, r, s):
    e = hash_file(file_path)
    v = inverse_mod(e, n)
    if v is None:
        return False
    z1 = (s * v) % n
    z2 = (-r * v) % n
    P1 = multiply_point((xG, yG), z1)
    P2 = multiply_point(Q, z2)
    P = add_points(P1, P2)
    if P is None:
        return False
    r1 = P[0] % n
    return r1 == r

def main():
    parser = argparse.ArgumentParser(description='GOST Р 34.10-2012 реализация')
    subparsers = parser.add_subparsers(dest='command')

    # Генерация ключей
    gen_parser = subparsers.add_parser('generate', help='Сгенерировать ключи')
    gen_parser.add_argument('private_key_file', help='Файл для сохранения приватного ключа')
    gen_parser.add_argument('public_key_file', help='Файл для сохранения публичного ключа')

    # Подписание
    sign_parser = subparsers.add_parser('sign', help='Подписать файл')
    sign_parser.add_argument('-k', '--private-key', required=True, help='Файл с приватным ключом')
    sign_parser.add_argument('file', help='Файл для подписи')
    sign_parser.add_argument('-o', '--output', required=True, help='Файл для сохранения подписи')

    # Проверка
    verify_parser = subparsers.add_parser('verify', help='Проверить подпись')
    verify_parser.add_argument('-K', '--public-key', required=True, help='Файл с публичным ключом')
    verify_parser.add_argument('file', help='Файл с данными')
    verify_parser.add_argument('signature', help='Файл с подписью')

    args = parser.parse_args()

    if args.command == 'generate':
        d, Q = generate_keys()
        with open(args.private_key_file, 'w') as f:
            f.write(str(d))
        with open(args.public_key_file, 'w') as f:
            f.write(f"{Q[0]},{Q[1]}")
        print(f"Ключи сгенерированы: {args.private_key_file}, {args.public_key_file}")

    elif args.command == 'sign':
        with open(args.private_key, 'r') as f:
            d = int(f.read())
        r, s = sign_file(args.file, d)
        with open(args.output, 'w') as f:
            f.write(f"{r},{s}")
        print(f"Файл подписан: {args.output}")

    elif args.command == 'verify':
        with open(args.public_key, 'r') as f:
            Q = tuple(map(int, f.read().split(',')))
        with open(args.signature, 'r') as f:
            r, s = map(int, f.read().split(','))
        valid = verify_signature(args.file, Q, r, s)
        print("Подпись действительна" if valid else "Подпись недействительна")

if __name__ == '__main__':
    main()
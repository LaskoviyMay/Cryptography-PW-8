import secrets
import argparse
import os
from Crypto.Hash import GOST34112012

# Параметры эллиптической кривой по ГОСТ Р 34.10-2012
PRIME = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97", 16)
COEFF_A = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94", 16)
COEFF_B = int("A6", 16)
ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893", 16)
BASE_X = int("1", 16)
BASE_Y = int("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14", 16)
START_POINT = (BASE_X, BASE_Y)

def inverse_modulo(value, modulus):
    """
    Вычисляет модульный обратный элемент для заданного числа по указанному модулю.

    Аргументы:
        value (int): Число, для которого ищется обратный элемент. Должно быть ненулевым и меньше modulus.
        modulus (int): Модуль, по которому производится вычисление. Обычно это простое число (в данном случае PRIME или ORDER).

    Возвращает:
        int: Обратный элемент value по модулю modulus, такой что (value * result) % modulus == 1.

    Исключения:
        ValueError: Возникает, если value равно 0, так как обратного элемента для нуля не существует.
    """
    if value == 0:
        raise ValueError("Деление на ноль невозможно")
    a, b = 1, 0
    low, high = value % modulus, modulus
    while low > 1:
        quotient = high // low
        a, b = b - a * quotient, a
        low, high = high - low * quotient, low
    return a % modulus

def curve_point_sum(p1, p2):
    """
    Выполняет сложение двух точек на эллиптической кривой, определенной параметрами PRIME, COEFF_A и COEFF_B.

    Аргументы:
        p1 (tuple или None): Первая точка на кривой в формате (x, y), где x и y — целые числа, или None (точка в бесконечности).
        p2 (tuple или None): Вторая точка на кривой в формате (x, y), где x и y — целые числа, или None (точка в бесконечности).

    Возвращает:
        tuple или None: Результирующая точка (x, y) на кривой или None, если результат — точка в бесконечности (например, при сложении противоположных точек).
    """
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % PRIME == 0:
        return None
    if p1 == p2:
        gradient = (3 * x1 * x1 + COEFF_A) * inverse_modulo(2 * y1, PRIME) % PRIME
    else:
        gradient = (y2 - y1) * inverse_modulo(x2 - x1, PRIME) % PRIME
    x_new = (gradient * gradient - x1 - x2) % PRIME
    y_new = (gradient * (x1 - x_new) - y1) % PRIME
    return (x_new, y_new)

def multiply_point(factor, point):
    """
    Умножает точку на эллиптической кривой на целое число методом "double-and-add".

    Аргументы:
        factor (int): Целый множитель, определяющий, сколько раз точка будет сложена с собой. Обычно от 1 до ORDER - 1.
        point (tuple): Точка на кривой в формате (x, y), где x и y — координаты точки (например, START_POINT).

    Возвращает:
        tuple или None: Результирующая точка (x, y) на кривой или None, если результат — точка в бесконечности.
    """
    current = None
    temp_point = point
    while factor > 0:
        if factor & 1:
            current = curve_point_sum(current, temp_point)
        temp_point = curve_point_sum(temp_point, temp_point)
        factor >>= 1
    return current

def compute_gost_hash(input_data):
    """
    Вычисляет хэш-значение данных по стандарту ГОСТ Р 34.11-2012 с использованием библиотеки pycryptodome.

    Аргументы:
        input_data (bytes): Входные данные в виде байтовой строки, которые нужно захэшировать (например, содержимое файла).

    Возвращает:
        int: Хэш-значение в виде целого числа, полученное из 256-битного хэша, преобразованного в integer.
    """
    try:
        hasher = GOST34112012.new(data=input_data)
        return int.from_bytes(hasher.digest(), byteorder='big')
    except Exception as e:
        print(f"Ошибка хэширования: {e}")
        return None

class DigitalSignature:
    def __init__(self):
        self.secret_key = None
        self.open_key = None

    def create_keypair(self):
        """
        Генерирует пару ключей для цифровой подписи по ГОСТ Р 34.10-2012: секретный и открытый ключи.

        Секретный ключ — случайное число от 1 до ORDER - 1.
        Открытый ключ — точка на эллиптической кривой, полученная как START_POINT * secret_key.
        """
        self.secret_key = secrets.randbelow(ORDER - 1) + 1
        self.open_key = multiply_point(self.secret_key, START_POINT)

    def generate_signature(self, data):
        """
        Создает электронную цифровую подпись для данных по ГОСТ Р 34.10-2012 с использованием секретного ключа.

        Аргументы:
            data (bytes): Данные, для которых создается подпись (например, содержимое файла в виде байтов).

        Возвращает:
            tuple: Подпись в формате (r, s), где r и s — целые числа, удовлетворяющие условиям алгоритма.
        """
        hash_val = compute_gost_hash(data) % ORDER
        if hash_val == 0:
            hash_val = 1
        while True:
            temp_k = secrets.randbelow(ORDER - 1) + 1
            temp_point = multiply_point(temp_k, START_POINT)
            if temp_point is None:
                continue
            r_val = temp_point[0] % ORDER
            if r_val == 0:
                continue
            s_val = (r_val * self.secret_key + temp_k * hash_val) % ORDER
            if s_val != 0:
                break
        return (r_val, s_val)

    def check_signature(self, data, signature, open_key):
        """
        Проверяет валидность цифровой подписи для данных с использованием открытого ключа.

        Аргументы:
            data (bytes): Данные, для которых была создана подпись (например, содержимое файла).
            signature (tuple): Подпись в формате (r, s), где r и s — целые числа.
            open_key (tuple): Открытый ключ в формате (x, y), где x и y — координаты точки на кривой.

        Возвращает:
            bool: True, если подпись верна, False — в противном случае.
        """
        r_val, s_val = signature
        if not (1 <= r_val < ORDER and 1 <= s_val < ORDER):
            return False
        hash_val = compute_gost_hash(data) % ORDER
        if hash_val == 0:
            hash_val = 1
        inverse_hash = inverse_modulo(hash_val, ORDER)
        u1 = (s_val * inverse_hash) % ORDER
        u2 = (-r_val * inverse_hash) % ORDER
        result_point = curve_point_sum(multiply_point(u1, START_POINT), multiply_point(u2, open_key))
        if result_point is None:
            return False
        return (result_point[0] % ORDER) == r_val

def write_data(filepath, value, is_pair=False):
    """
    Записывает данные (число или пару чисел) в файл в шестнадцатеричном формате.

    Аргументы:
        filepath (str): Путь к файлу, в который производится запись (например, 'secret.key').
        value (int или tuple): Значение для записи: либо целое число, либо кортеж (x, y) для точек или подписей.
        is_pair (bool): Если True, value интерпретируется как пара чисел (x, y), например, для ключа или подписи.
    """
    try:
        with open(filepath, 'w') as file:
            if is_pair:
                file.write(f"{value[0]:x}\n{value[1]:x}")
            else:
                file.write(f"{value:x}")
    except Exception as e:
        print(f"Ошибка записи в файл {filepath}: {e}")

def read_data(filepath, is_pair=False):
    """
    Читает данные из файла, интерпретируя их как шестнадцатеричные числа.

    Аргументы:
        filepath (str): Путь к файлу, из которого читаются данные (например, 'secret.key').
        is_pair (bool): Если True, ожидается, что файл содержит две строки (x, y) для точки или подписи.

    Возвращает:
        int или tuple: Прочитанное значение: либо целое число, либо кортеж (x, y), если is_pair=True.
    """
    try:
        with open(filepath, 'r') as file:
            content = file.read().splitlines()
            if is_pair:
                return (int(content[0], 16), int(content[1], 16))
            return int(content[0], 16)
    except Exception as e:
        print(f"Ошибка чтения файла {filepath}: {e}")
        return None

def process_arguments():
    parser = argparse.ArgumentParser(description="Цифровая подпись ГОСТ Р 34.10-2012")
    parser.add_argument("--create-keys", nargs=2, metavar=("secret", "open"), help="Создать ключи")
    parser.add_argument("--sign-data", nargs=3, metavar=("data", "secret", "sig"), help="Подписать файл")
    parser.add_argument("--validate", nargs=3, metavar=("data", "open", "sig"), help="Проверить подпись")
    return parser.parse_args()

def main():
    args = process_arguments()
    signature_tool = DigitalSignature()

    if args.create_keys:
        secret_path, open_path = args.create_keys
        signature_tool.create_keypair()
        write_data(secret_path, signature_tool.secret_key)
        write_data(open_path, signature_tool.open_key, is_pair=True)
        print(f"Ключи созданы: {secret_path} (секретный), {open_path} (открытый)")

    elif args.sign_data:
        data_path, secret_path, sig_path = args.sign_data
        if not os.path.exists(data_path) or not os.path.exists(secret_path):
            print("Файл данных или секретный ключ отсутствует")
            return
        with open(data_path, "rb") as file:
            content = file.read()
        signature_tool.secret_key = read_data(secret_path)
        if signature_tool.secret_key is None:
            return
        signature = signature_tool.generate_signature(content)
        write_data(sig_path, signature, is_pair=True)
        print(f"Подпись создана в файле: {sig_path}")

    elif args.validate:
        data_path, open_path, sig_path = args.validate
        if not all(os.path.exists(p) for p in [data_path, open_path, sig_path]):
            print("Один из файлов отсутствует")
            return
        with open(data_path, "rb") as file:
            content = file.read()
        open_key = read_data(open_path, is_pair=True)
        signature = read_data(sig_path, is_pair=True)
        if open_key is None or signature is None:
            return
        is_valid = signature_tool.check_signature(content, signature, open_key)
        print("Подпись подтверждена" if is_valid else "Подпись не подтверждена")

    else:
        print("Ошибка")

if __name__ == "__main__":
    main()
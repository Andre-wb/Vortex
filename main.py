import time
import hashlib
import vortex

# =====================================
# Rust функции
# =====================================
def rust_hash_string(s):
    return vortex.hash_string(s)

def rust_hash_bytes(b):
    return vortex.hash_bytes(b)

def rust_xor_encrypt(data, key):
    return vortex.xor_encrypt(data, key)

# =====================================
# Python аналоги
# =====================================
def py_hash_string(s):
    return hashlib.sha256(s.encode()).hexdigest()

def py_hash_bytes(b):
    return hashlib.sha256(b).hexdigest()

def py_xor_encrypt(data, key):
    return bytes(b ^ key for b in data)

# =====================================
# ТЕСТ 1: Хэширование строк
# =====================================
print("=" * 60)
print("ТЕСТ 1: ХЭШИРОВАНИЕ СТРОК (100,000 итераций)")
print("=" * 60)

test_str = "Hello P2P!" * 100

start = time.time()
for i in range(100000):
    py_hash_string(test_str)
py_time = time.time() - start
print(f"Python:  {py_time:.4f} сек")

start = time.time()
for i in range(100000):
    rust_hash_string(test_str)
rust_time = time.time() - start
print(f"Rust:    {rust_time:.4f} сек")

print(f"Ускорение: {py_time/rust_time:.1f}x")

# =====================================
# ТЕСТ 2: Хэширование байт
# =====================================
print("\n" + "=" * 60)
print("ТЕСТ 2: ХЭШИРОВАНИЕ БАЙТ (100,000 итераций)")
print("=" * 60)

# Убрали эмодзи!
test_bytes = b"Hello P2P!" * 100

start = time.time()
for i in range(100000):
    py_hash_bytes(test_bytes)
py_time = time.time() - start
print(f"Python:  {py_time:.4f} сек")

start = time.time()
for i in range(100000):
    rust_hash_bytes(test_bytes)
rust_time = time.time() - start
print(f"Rust:    {rust_time:.4f} сек")

print(f"Ускорение: {py_time/rust_time:.1f}x")

# =====================================
# ТЕСТ 3: XOR шифрование
# =====================================
print("\n" + "=" * 60)
print("ТЕСТ 3: XOR ШИФРОВАНИЕ (100,000 итераций)")
print("=" * 60)

test_data = b"Secret message for P2P network" * 10
key = 42

start = time.time()
for i in range(100000):
    py_xor_encrypt(test_data, key)
py_time = time.time() - start
print(f"Python:  {py_time:.4f} сек")

start = time.time()
for i in range(100000):
    rust_xor_encrypt(test_data, key)
rust_time = time.time() - start
print(f"Rust:    {rust_time:.4f} сек")

print(f"Ускорение: {py_time/rust_time:.1f}x")

# =====================================
# ТЕСТ 4: P2PNode класс
# =====================================
print("\n" + "=" * 60)
print("ТЕСТ 4: P2PNODE КЛАСС")
print("=" * 60)

print("\nСоздание 10,000 узлов:")
start = time.time()
nodes = []
for i in range(10000):
    nodes.append(vortex.P2PNode(f"node{i}"))
create_time = time.time() - start
print(f"Rust: {create_time:.4f} сек")

print("\nДобавление пиров (100,000 операций):")
node = vortex.P2PNode("test")
start = time.time()
for i in range(100000):
    node.add_peer(f"peer{i}")
add_time = time.time() - start
print(f"Rust: {add_time:.4f} сек")

print("\nПолучение списка пиров (100,000 раз):")
start = time.time()
for i in range(100000):
    peers = node.get_peers()
get_time = time.time() - start
print(f"Rust: {get_time:.4f} сек")

# =====================================
# ИТОГИ
# =====================================
print("\n" + "=" * 60)
print("ГОТОВО!")
print("=" * 60)
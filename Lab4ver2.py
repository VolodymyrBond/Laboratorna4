# робимо імпорт бібліотек 
import ssl
import socket
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from datetime import datetime, timedelta


def generate_certificates():    # Функція для генерації приватного ключа і самопідписаного сертифіката
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open("server.key", "wb") as f:                                # збереження ключа 
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    subject = issuer = x509.Name([       # створення самого сертифікату 
        x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kyiv"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (          # створюється сертифікат (термін дії - 365 днів)
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    with open("server.crt", "wb") as f:    # збереження сертифікату 
        f.write(cert.public_bytes(Encoding.PEM))
    print("Сертифікати згенеровано: server.key, server.crt")


def handle_client(conn, addr):             # функція, яка відповідає за дії клієнта, такі як отримання даних від нього та відправка відповіді.
    print(f"Підключення від {addr}")
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data or data.lower() == "exit":
                print(f"Клієнт {addr} завершив з'єднання.")
                break
            print(f"Від {addr}: {data}")
            response = f"Сервер отримав: {data}"
            conn.send(response.encode())
    finally:
        conn.close()


def run_server():          # функція для запуску сервера. 
    HOST = "localhost"
    PORT = 12345

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)       # налаштування SSL сервера 
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as server_socket:     # створюється сокет і запускається сервер 
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Сервер запущено на {HOST}:{PORT}")
        with context.wrap_socket(server_socket, server_side=True) as tls_socket:
            while True:
                client_conn, client_addr = tls_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(client_conn, client_addr))
                client_thread.start()


def run_client():              # дана функція запускає клієнта
    HOST = "localhost"
    PORT = 12345

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("server.crt")

    with socket.create_connection((HOST, PORT)) as sock:           # відбувається підключення до сервера SSL
        with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
            print("Підключено до сервера через SSL.")
            try:
                while True:
                    message = input("Введіть повідомлення (або 'exit' для виходу): ")       # зчитування повідомлення від користувача
                    tls_sock.send(message.encode())
                    if message.lower() == "exit":
                        print("З'єднання закрито.")
                        break
                    response = tls_sock.recv(1024).decode()                    # відповідь від сервера
                    print(f"Відповідь сервера: {response}")
            except KeyboardInterrupt:
                print("\nЗавершення роботи клієнта.")
            finally:
                tls_sock.close()

# далі відбувається запуск програми
if __name__ == "__main__":
    generate_certificates()


    server_thread = threading.Thread(target=run_server, daemon=True)       # запуск сервера та клієнта
    server_thread.start()

 
    import time
    time.sleep(1)


    run_client()

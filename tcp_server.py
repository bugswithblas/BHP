import socket
import threading

bind_ip = "127.0.0.1"
bind_port = 9090

def main():
    server = socket.socket(socket.AF_INET)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print(f"Server is listening on {bind_ip}:{bind_port}")

    while True:
        client, address = server.accept()
        print(f"Connection accepted from {address[0]}:{address[1]}")
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f"Received: {request.decode("utf-8")}")
        sock.send(b'ACK')

if __name__ == '__main__':
    main()
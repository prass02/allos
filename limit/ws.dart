import 'dart:io';
import 'dart:async';
import 'dart:convert';

const String LISTENING_ADDR = '127.0.0.1';
const int LISTENING_PORT = 777;
const int BUFLEN = 4096 * 4;
const int TIMEOUT = 60;
const String DEFAULT_HOST = '127.0.0.1:109';
const String RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\n\r\n';
const String PASS = '';

void main() {
  print("\n:-------DartProxy-------:\n");
  print("Listening addr: $LISTENING_ADDR");
  print("Listening port: $LISTENING_PORT\n");
  print(":-------------------------:\n");

  Server server = Server(LISTENING_ADDR, LISTENING_PORT);
  server.start();
}

class Server {
  final String host;
  final int port;
  bool running = false;
  ServerSocket? _serverSocket;
  List<ConnectionHandler> connections = [];

  Server(this.host, this.port);

  Future<void> start() async {
    try {
      _serverSocket = await ServerSocket.bind(host, port);
      running = true;
      print("Server started on $host:$port");

      await for (Socket client in _serverSocket!) {
        ConnectionHandler handler = ConnectionHandler(client, this);
        connections.add(handler);
        handler.start();
      }
    } catch (e) {
      print("Server error: $e");
    }
  }

  void removeConnection(ConnectionHandler conn) {
    connections.remove(conn);
  }

  void stop() {
    running = false;
    _serverSocket?.close();
    for (var conn in connections) {
      conn.close();
    }
    print("Server stopped.");
  }
}

class ConnectionHandler {
  final Socket client;
  final Server server;
  bool clientClosed = false;
  bool targetClosed = true;
  Socket? target;
  String log = '';

  ConnectionHandler(this.client, this.server) {
    log = 'Connection from: ${client.remoteAddress.address}:${client.remotePort}';
  }

  void start() async {
    try {
      List<int> clientBuffer = await client.first;
      String header = utf8.decode(clientBuffer);

      String hostPort = findHeader(header, 'X-Real-Host') ?? DEFAULT_HOST;

      if (findHeader(header, 'X-Split') != null) {
        await client.first; // Read next data chunk
      }

      if (hostPort.isNotEmpty) {
        String? passwd = findHeader(header, 'X-Pass');
        if (PASS.isNotEmpty && passwd == PASS) {
          await method_CONNECT(hostPort);
        } else if (PASS.isNotEmpty && passwd != PASS) {
          client.write('HTTP/1.1 400 WrongPass!\r\n\r\n');
        } else if (hostPort.startsWith('127.0.0.1') || hostPort.startsWith('localhost')) {
          await method_CONNECT(hostPort);
        } else {
          client.write('HTTP/1.1 403 Forbidden!\r\n\r\n');
        }
      } else {
        print('- No X-Real-Host!');
        client.write('HTTP/1.1 400 NoXRealHost!\r\n\r\n');
      }
    } catch (e) {
      print('Error: $e');
    } finally {
      close();
      server.removeConnection(this);
    }
  }

  String? findHeader(String header, String key) {
    RegExp regex = RegExp('$key: (.+)');
    Match? match = regex.firstMatch(header);
    return match != null ? match.group(1) : null;
  }

  Future<void> connectTarget(String host) async {
    try {
      List<String> parts = host.split(':');
      String hostname = parts[0];
      int port = parts.length > 1 ? int.parse(parts[1]) : 443;

      target = await Socket.connect(hostname, port);
      targetClosed = false;
    } catch (e) {
      print('Target connection error: $e');
      targetClosed = true;
    }
  }

  Future<void> method_CONNECT(String path) async {
    log += ' - CONNECT $path';
    await connectTarget(path);

    if (target != null) {
      client.write(RESPONSE);
      await doCONNECT();
    }
  }

  Future<void> doCONNECT() async {
    if (target == null) return;

    StreamSubscription? clientSub;
    StreamSubscription? targetSub;

    clientSub = client.listen((data) {
      if (!targetClosed) {
        target?.add(data);
      }
    }, onDone: () {
      close();
      clientSub?.cancel();
    });

    targetSub = target?.listen((data) {
      if (!clientClosed) {
        client.add(data);
      }
    }, onDone: () {
      close();
      targetSub?.cancel();
    });
  }

  void close() {
    if (!clientClosed) {
      client.destroy();
      clientClosed = true;
    }
    if (!targetClosed) {
      target?.destroy();
      targetClosed = true;
    }
  }
}

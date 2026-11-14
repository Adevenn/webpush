import 'dart:io';

/// A client that only connects to [address], keeping the TLS check on the
/// requested name.
/// Un client qui ne se connecte qu'à [address], en gardant la
/// vérification TLS sur le nom demandé.
HttpClient pinnedHttpClient(InternetAddress address, Duration timeout) {
  final client = HttpClient()
    ..findProxy = ((_) => 'DIRECT')
    ..autoUncompress = true
    ..connectionTimeout = timeout;
  client.connectionFactory = (uri, proxyHost, proxyPort) async {
    final task = await Socket.startConnect(address, uri.port);
    if (uri.scheme != 'https') return task;
    return ConnectionTask.fromSocket(
      task.socket.then((socket) => SecureSocket.secure(socket, host: uri.host)),
      task.cancel,
    );
  };
  return client;
}

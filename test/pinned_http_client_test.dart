import 'dart:io';

import 'package:test/test.dart';
import 'package:webpush/src/pinned_http_client.dart';

void main() {
  group('pinnedHttpClient', () {
    late HttpServer server;
    final hosts = <String?>[];

    setUp(() async {
      hosts.clear();
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((request) async {
        hosts.add(request.headers.value(HttpHeaders.hostHeader));
        request.response.statusCode = HttpStatus.created;
        await request.response.close();
      });
    });

    tearDown(() => server.close(force: true));

    test('connects to the pinned address, whatever the name', () async {
      // `.invalid` never resolves (RFC 6761): reaching the server proves
      // that no lookup was made.
      // `.invalid` ne se résout jamais (RFC 6761) : atteindre le serveur
      // prouve qu'aucune résolution n'a eu lieu.
      final client = pinnedHttpClient(
        InternetAddress.loopbackIPv4,
        const Duration(seconds: 5),
      );
      addTearDown(() => client.close(force: true));
      final request = await client.postUrl(
        Uri.parse('http://push.example.invalid:${server.port}/x'),
      );
      final response = await request.close();
      await response.drain<void>();
      expect(response.statusCode, HttpStatus.created);
      expect(hosts.single, 'push.example.invalid:${server.port}');
    });
  });
}

import 'dart:io';

import 'package:webpush/webpush.dart';

final browser = P256KeyPair.generate();
final browserAuth = List<int>.generate(16, (i) => i);

PushSubscription device(String id, String user, {String? endpoint}) =>
    PushSubscription(
      id: id,
      userId: user,
      endpoint:
          endpoint ?? 'https://updates.push.services.mozilla.com/wpush/v2/$id',
      p256dh: base64UrlNoPad(browser.publicBytes),
      auth: base64UrlNoPad(browserAuth),
    );

class Sent {
  Sent(this.endpoint, this.headers, this.body);

  final Uri endpoint;
  final Map<String, String> headers;
  final List<int> body;
}

class FakePush {
  final sent = <Sent>[];
  int status = HttpStatus.created;
  final statusByEndpoint = <String, int>{};
  bool fail = false;

  Future<int> call(Uri endpoint, Map<String, String> headers, List<int> body) {
    if (fail) throw const SocketException('down');
    sent.add(Sent(endpoint, headers, body));
    return Future.value(statusByEndpoint['$endpoint'] ?? status);
  }
}

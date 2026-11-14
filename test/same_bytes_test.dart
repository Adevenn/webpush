import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:webpush/webpush.dart';

// Wire bytes frozen from Puffin's worker (see tool/puffin_reference/): with
// the same salt, sender key, VAPID key and clock, the package must send the
// very same headers and body. Never regenerate this file to make it pass.
// Octets figés depuis le worker de Puffin (voir tool/puffin_reference/) :
// à sel, clé d'expéditeur, clé VAPID et horloge égaux, le paquet doit envoyer
// exactement les mêmes en-têtes et le même corps. Ne jamais régénérer ce
// fichier pour faire passer le test.
void main() {
  final reference = jsonDecode(
    File('test/fixtures/puffin_reference.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final inputs = reference['inputs'] as Map<String, dynamic>;
  final cases = reference['cases'] as List<dynamic>;

  test('the reference holds the three cases', () {
    expect(cases, hasLength(3));
  });

  for (final c in cases.cast<Map<String, dynamic>>()) {
    test('same bytes as Puffin: ${c['name']}', () async {
      final m = c['message'] as Map<String, dynamic>;
      final sent = <(Map<String, String>, List<int>)>[];
      final sender = PushSender(
        keys: VapidKeys.parse(inputs['vapidPrivate'] as String),
        subject: inputs['subject'] as String,
        clock: () => DateTime.parse(inputs['now'] as String),
        transport: (endpoint, headers, body) async {
          sent.add((headers, body));
          return HttpStatus.created;
        },
        encrypt:
            ({required uaPublic, required authSecret, required plaintext}) =>
                encryptWebPush(
                  uaPublic: uaPublic,
                  authSecret: authSecret,
                  plaintext: plaintext,
                  senderKeys: P256KeyPair.fromPrivate(
                    decodeBase64Url(inputs['senderPrivate'] as String),
                  ),
                  salt: decodeBase64Url(inputs['salt'] as String),
                ),
      );
      final outcome = await sender.send(
        PushSubscription(
          id: 'd1',
          userId: 'u1',
          endpoint: c['endpoint'] as String,
          p256dh: inputs['uaPublic'] as String,
          auth: inputs['authSecret'] as String,
        ),
        PushMessage(
          title: m['title'] as String,
          body: m['body'] as String,
          tag: m['tag'] as String,
          tab: m['tab'] as String?,
        ),
        ttl: Duration(seconds: c['ttlSeconds'] as int),
        urgent: c['urgent'] as bool,
      );
      expect(outcome, PushOutcome.delivered);
      final (headers, body) = sent.single;
      final expected = Map<String, String>.from(c['headers'] as Map);
      // Same names, same order, same values.
      // Mêmes noms, même ordre, mêmes valeurs.
      expect(headers.keys.toList(), expected.keys.toList());
      expect(headers, expected);
      expect(base64UrlNoPad(body), c['body']);
    });
  }
}

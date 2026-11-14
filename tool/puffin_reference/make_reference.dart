// Produces test/fixtures/puffin_reference.json from Puffin's worker code, run
// ONCE inside a temporary copy of Puffin's `worker/` (Puffin itself is never
// modified). Kept here so the reference can be traced and checked again.
// Produit test/fixtures/puffin_reference.json avec le code du worker de
// Puffin, lancé UNE fois dans une copie temporaire de `worker/` (Puffin n'est
// jamais modifié). Gardé ici pour tracer et revérifier la référence.
//
// Usage, from the copy of `worker/` / depuis la copie de `worker/` :
//   dart run tool/make_reference.dart <puffin commit> > puffin_reference.json
//
// Headers come from the real PushSender.send (fixed VAPID key and clock).
// The body comes from encryptWebPush with a fixed sender key and salt, which
// is the very call that send makes with random ones.
// Les en-têtes viennent du vrai PushSender.send (clé VAPID et horloge fixes).
// Le corps vient d'encryptWebPush avec clé d'expéditeur et sel fixes : c'est
// l'appel même que fait send, avec des valeurs aléatoires.
import 'dart:convert';
import 'dart:io';

import 'package:puffin_worker/puffin_worker.dart';

// Test values only, all public (RFC 8291 §5 and a made-up VAPID key).
// Valeurs de test uniquement, toutes publiques (RFC 8291 §5 et une clé
// VAPID inventée).
const vapidPrivate = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
const uaPublic =
    'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx'
    'aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4';
const authSecret = 'BTBZMqHH6r4Tts7J_aSIgg';
const senderPrivate = 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw';
const salt = 'DGv6ra1nlYgDCS1FRnbzlw';
const subject = 'mailto:contact@example.org';
const now = '2026-11-02T12:00:00.000Z';

const cases = [
  {
    'name': 'apple-normal',
    'endpoint': 'https://web.push.apple.com/QExampleToken',
    'ttlSeconds': 7200,
    'urgent': false,
    'message': {
      'title': 'Sauvegarde terminée',
      'body': 'Tout est à jour ✅',
      'tag': 'backup:nightly',
      'tab': 'planning',
    },
  },
  {
    'name': 'apple-urgent-ttl-clamped',
    'endpoint': 'https://web.push.apple.com/QExampleToken',
    'ttlSeconds': 3 * 24 * 3600,
    'urgent': true,
    'message': {'title': '⏰ Minuteur', 'body': 'Fini', 'tag': 't:abc'},
  },
  {
    'name': 'mozilla-negative-ttl',
    'endpoint': 'https://updates.push.services.mozilla.com/wpush/v2/abc',
    'ttlSeconds': -300,
    'urgent': false,
    'message': {'title': 'T', 'body': 'B', 'tag': 'x'},
  },
];

Future<void> main(List<String> args) async {
  final keys = VapidKeys.parse(vapidPrivate);
  final sender = P256KeyPair.fromPrivate(decodeBase64Url(senderPrivate));
  final out = <Map<String, Object?>>[];
  for (final c in cases) {
    final m = c['message'] as Map<String, String>;
    final message = PushMessage(
      title: m['title']!,
      body: m['body']!,
      tag: m['tag']!,
      tab: m['tab'],
    );
    final subscription = PushSubscription(
      id: 'd1',
      userId: 'u1',
      endpoint: c['endpoint'] as String,
      p256dh: uaPublic,
      auth: authSecret,
    );
    late Map<String, String> headers;
    late List<int> randomBody;
    final outcome =
        await PushSender(
          keys: keys,
          subject: subject,
          clock: () => DateTime.parse(now),
          transport: (endpoint, h, body) async {
            headers = h;
            randomBody = body;
            return HttpStatus.created;
          },
        ).send(
          subscription,
          message,
          ttl: Duration(seconds: c['ttlSeconds'] as int),
          urgent: c['urgent'] as bool,
        );
    final body = encryptWebPush(
      uaPublic: decodeBase64Url(uaPublic),
      authSecret: decodeBase64Url(authSecret),
      plaintext: message.encode(),
      senderKeys: sender,
      salt: decodeBase64Url(salt),
    );
    if (outcome != PushOutcome.delivered || randomBody.length != body.length) {
      throw StateError('unexpected send result for ${c['name']}');
    }
    out.add({...c, 'headers': headers, 'body': base64UrlNoPad(body)});
  }
  stdout.writeln(
    const JsonEncoder.withIndent('  ').convert({
      'source': {
        'repository': 'Puffin',
        'commit': args.single,
        'files': 'worker/lib/src/{push_crypto,vapid,push_sender}.dart',
      },
      'inputs': {
        'vapidPrivate': vapidPrivate,
        'subject': subject,
        'now': now,
        'uaPublic': uaPublic,
        'authSecret': authSecret,
        'senderPrivate': senderPrivate,
        'salt': salt,
      },
      'cases': out,
    }),
  );
}

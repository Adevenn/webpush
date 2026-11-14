import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:webpush/webpush.dart';

import 'support/fake_push.dart';

void main() {
  final keys = VapidKeys.generate();

  group('push endpoints', () {
    test('only Apple and Mozilla, https on 443', () {
      for (final ok in [
        'https://web.push.apple.com/abc',
        'https://updates.push.services.mozilla.com/wpush/v2/abc',
      ]) {
        expect(isAllowedPushEndpoint(Uri.parse(ok)), isTrue, reason: ok);
      }
      for (final bad in [
        'http://web.push.apple.com/abc',
        'https://web.push.apple.com:8443/abc',
        'https://user@web.push.apple.com/abc',
        'https://push.apple.com.evil.test/abc',
        'https://evilpush.apple.com/abc',
        'https://fcm.googleapis.com/fcm/send/abc',
        'https://127.0.0.1/abc',
      ]) {
        expect(isAllowedPushEndpoint(Uri.parse(bad)), isFalse, reason: bad);
      }
    });
  });

  group('PushSender', () {
    late FakePush push;
    late PushSender sender;
    const message = PushMessage(
      title: 'T',
      body: 'B',
      tag: 'x',
      tab: 'planning',
    );

    setUp(() {
      push = FakePush();
      sender = PushSender(
        keys: keys,
        subject: 'mailto:contact@example.org',
        transport: push.call,
        clock: () => DateTime.utc(2026, 11, 2),
      );
    });

    test('encrypted body and the Web Push headers', () async {
      final outcome = await sender.send(
        device('d1', 'u1'),
        message,
        ttl: const Duration(hours: 2),
      );
      expect(outcome, PushOutcome.delivered);
      final s = push.sent.single;
      expect(s.headers['ttl'], '7200');
      expect(s.headers['urgency'], 'normal');
      expect(s.headers['content-encoding'], 'aes128gcm');
      expect(s.headers['authorization'], startsWith('vapid t='));
      expect(s.headers['authorization'], endsWith('k=${keys.publicKey}'));
      // Header: salt, record size 4096, then the sender's 65-byte key.
      expect(s.body.sublist(16, 21), [0, 0, 16, 0, 65]);
      expect(utf8.decode(s.body, allowMalformed: true), isNot(contains('"T"')));
    });

    test('TTL clamped, urgency for timers', () async {
      await sender.send(
        device('d1', 'u1'),
        message,
        ttl: const Duration(days: 3),
        urgent: true,
      );
      await sender.send(
        device('d1', 'u1'),
        message,
        ttl: const Duration(minutes: -5),
      );
      expect(push.sent[0].headers['ttl'], '86400');
      expect(push.sent[0].headers['urgency'], 'high');
      expect(push.sent[1].headers['ttl'], '0');
    });

    test('outcomes', () async {
      Future<PushOutcome> with_(int status) {
        push.status = status;
        return sender.send(device('d1', 'u1'), message, ttl: Duration.zero);
      }

      expect(await with_(HttpStatus.gone), PushOutcome.gone);
      expect(await with_(HttpStatus.notFound), PushOutcome.gone);
      expect(await with_(HttpStatus.tooManyRequests), PushOutcome.failed);
      push.fail = true;
      expect(await with_(HttpStatus.created), PushOutcome.failed);
    });

    test('a foreign endpoint or broken keys are never contacted', () async {
      final foreign = device('d1', 'u1', endpoint: 'https://evil.test/push');
      expect(
        await sender.send(foreign, message, ttl: Duration.zero),
        PushOutcome.invalid,
      );
      final broken = PushSubscription(
        id: 'd2',
        userId: 'u1',
        endpoint: 'https://web.push.apple.com/x',
        p256dh: 'AAAA',
        auth: 'AAAA',
      );
      expect(
        await sender.send(broken, message, ttl: Duration.zero),
        PushOutcome.invalid,
      );
      expect(push.sent, isEmpty);
    });
  });
}

import 'dart:io';

import 'package:test/test.dart';
import 'package:webpush/webpush.dart';

import 'support/fake_push.dart';

void main() {
  final keys = VapidKeys.generate();
  const message = PushMessage(title: 'T', body: 'B', tag: 'x');
  const apple = 'https://web.push.apple.com/abc';
  const mozilla = 'https://updates.push.services.mozilla.com/wpush/v2/abc';

  late FakePush push;

  PushSender senderWith({PushServices services = PushServices.defaults}) =>
      PushSender(
        keys: keys,
        subject: 'mailto:contact@example.org',
        transport: push.call,
        clock: () => DateTime.utc(2026, 11, 2),
        services: services,
      );

  setUp(() => push = FakePush());

  group('urgency', () {
    test('each level gives its RFC 8030 header', () async {
      final sender = senderWith();
      for (final level in PushUrgency.values) {
        await sender.send(
          device('d1', 'u1'),
          message,
          ttl: Duration.zero,
          urgency: level,
        );
      }
      expect(push.sent.map((s) => s.headers['urgency']), [
        'very-low',
        'low',
        'normal',
        'high',
      ]);
    });

    test('without urgency, urgent keeps giving high or normal', () async {
      final sender = senderWith();
      await sender.send(device('d1', 'u1'), message, ttl: Duration.zero);
      await sender.send(
        device('d1', 'u1'),
        message,
        ttl: Duration.zero,
        urgent: true,
      );
      expect(push.sent.map((s) => s.headers['urgency']), ['normal', 'high']);
    });

    test('urgent and urgency together are refused, nothing sent', () async {
      await expectLater(
        senderWith().send(
          device('d1', 'u1'),
          message,
          ttl: Duration.zero,
          urgent: true,
          urgency: PushUrgency.low,
        ),
        throwsArgumentError,
      );
      expect(push.sent, isEmpty);
    });
  });

  group('push services', () {
    test('the defaults are Apple and Mozilla, as before', () {
      expect(PushServices.defaults.hosts, pushHosts);
      expect(PushServices.defaults.hostSuffixes, pushHostSuffixes);
      expect(isAllowedPushEndpoint(Uri.parse(apple)), isTrue);
      expect(isAllowedPushEndpoint(Uri.parse(mozilla)), isTrue);
    });

    test('a custom list allows only its own services', () {
      const onlyApple = PushServices(hostSuffixes: ['.push.apple.com']);
      expect(isAllowedPushEndpoint(Uri.parse(apple), onlyApple), isTrue);
      expect(isAllowedPushEndpoint(Uri.parse(mozilla), onlyApple), isFalse);
      const onlyMozilla = PushServices(
        hosts: {'updates.push.services.mozilla.com'},
      );
      expect(isAllowedPushEndpoint(Uri.parse(mozilla), onlyMozilla), isTrue);
      expect(isAllowedPushEndpoint(Uri.parse(apple), onlyMozilla), isFalse);
    });

    test('an empty list refuses everything', () {
      const none = PushServices();
      expect(isAllowedPushEndpoint(Uri.parse(apple), none), isFalse);
      expect(isAllowedPushEndpoint(Uri.parse(mozilla), none), isFalse);
    });

    test('case is ignored, https on 443 still required', () {
      const custom = PushServices(
        hosts: {'Push.Example.Org'},
        hostSuffixes: ['.PUSH.example.net'],
      );
      for (final ok in [
        'https://push.example.org/a',
        'https://PUSH.EXAMPLE.ORG/a',
        'https://eu.push.example.net/a',
      ]) {
        expect(
          isAllowedPushEndpoint(Uri.parse(ok), custom),
          isTrue,
          reason: ok,
        );
      }
      for (final bad in [
        'http://push.example.org/a',
        'https://push.example.org:8443/a',
        'https://user@push.example.org/a',
        'https://push.example.net/a',
        'https://push.example.net.evil.test/a',
      ]) {
        expect(
          isAllowedPushEndpoint(Uri.parse(bad), custom),
          isFalse,
          reason: bad,
        );
      }
    });

    test('a suffix without its leading dot never matches', () {
      const sloppy = PushServices(hostSuffixes: ['push.apple.com']);
      expect(
        isAllowedPushEndpoint(
          Uri.parse('https://evilpush.apple.com/a'),
          sloppy,
        ),
        isFalse,
      );
      expect(isAllowedPushEndpoint(Uri.parse(apple), sloppy), isFalse);
    });

    test('the sender refuses a service missing from its list', () async {
      final sender = senderWith(
        services: const PushServices(
          hosts: {'updates.push.services.mozilla.com'},
        ),
      );
      final toApple = device('d1', 'u1', endpoint: apple);
      expect(
        await sender.send(toApple, message, ttl: Duration.zero),
        PushOutcome.invalid,
      );
      expect(push.sent, isEmpty);
      expect(
        await sender.send(device('d2', 'u1'), message, ttl: Duration.zero),
        PushOutcome.delivered,
      );
    });
  });

  group('safePushTransport', () {
    test('refuses a name that resolves to a private address', () async {
      await expectLater(
        safePushTransport(Uri.parse('https://localhost/push'), const {}, [1]),
        throwsA(isA<SocketException>()),
      );
    });
  });
}

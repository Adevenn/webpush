import 'dart:io';

import 'package:webpush/src/address_policy.dart';
import 'package:test/test.dart';

InternetAddress ip(String text) => InternetAddress(text);

void main() {
  group('isPublicAddress', () {
    const blocked = [
      '0.0.0.0',
      '0.1.2.3',
      '10.0.0.1',
      '10.255.255.255',
      '100.64.0.1',
      '100.100.100.100', // Tailscale DNS / DNS de Tailscale
      '100.127.255.254',
      '127.0.0.1',
      '127.1.2.3',
      '169.254.169.254', // cloud metadata / métadonnées cloud
      '172.16.0.1',
      '172.31.255.255',
      '192.0.0.8',
      '192.0.2.1',
      '192.88.99.1',
      '192.168.1.1',
      '198.18.0.1',
      '198.19.255.255',
      '198.51.100.7',
      '203.0.113.9',
      '224.0.0.1',
      '239.255.255.250',
      '240.0.0.1',
      '255.255.255.255',
      '::',
      '::1',
      '::ffff:127.0.0.1',
      '::ffff:10.0.0.1',
      '::ffff:192.168.0.1',
      '::127.0.0.1', // IPv4-compatible / IPv4 compatible
      '64:ff9b::a00:1', // NAT64
      'fc00::1',
      'fd00::1',
      'fd7a:115c:a1e0::1', // Tailscale
      'fe80::1',
      'fec0::1',
      'ff02::1',
      '2001:db8::1',
      '2001::1', // Teredo
      '2002:c0a8:101::1', // 6to4
      '100::1',
    ];
    const public = [
      '1.1.1.1',
      '8.8.8.8',
      '93.184.216.34',
      '100.63.255.255',
      '100.128.0.0',
      '172.15.255.255',
      '172.32.0.0',
      '192.169.0.1',
      '198.20.0.1',
      '223.255.255.255',
      '::ffff:8.8.8.8',
      '2606:4700:4700::1111',
      '2a00:1450:4007:80f::200e',
    ];

    for (final a in blocked) {
      test('refuses $a', () => expect(isPublicAddress(ip(a)), isFalse));
    }
    for (final a in public) {
      test('allows $a', () => expect(isPublicAddress(ip(a)), isTrue));
    }
  });
}

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';
import 'package:webpush/src/push_crypto.dart';
import 'package:webpush/src/vapid.dart';
import 'package:test/test.dart';

Uint8List b64(String text) => decodeBase64Url(text);

void main() {
  group('RFC 8188 §3.1', () {
    test('« I am the walrus » encrypts to the published body', () {
      final body = encryptAes128gcm(
        ikm: b64('yqdlZ-tYemfogSmv7Ws5PQ'),
        salt: b64('I1BsxtFttlv3u_Oo94xnmw'),
        plaintext: utf8.encode('I am the walrus'),
      );
      expect(
        base64UrlNoPad(body),
        'I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-'
        'ly8Thjg',
      );
    });
  });

  group('RFC 8291 §5 and appendix A', () {
    final uaPublic = b64(
      'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx'
      'aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
    );
    final sender = P256KeyPair.fromPrivate(
      b64('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw'),
    );
    final authSecret = b64('BTBZMqHH6r4Tts7J_aSIgg');
    final salt = b64('DGv6ra1nlYgDCS1FRnbzlw');

    test('sender public key derived from its private key', () {
      expect(
        base64UrlNoPad(sender.publicBytes),
        'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg'
        'Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
      );
    });

    test('intermediate values', () {
      final ecdh = ecdhP256(sender.privateKey, decodeP256PublicKey(uaPublic));
      expect(
        base64UrlNoPad(ecdh),
        'kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs',
      );
      final prkKey = hkdfExtract(authSecret, ecdh);
      expect(
        base64UrlNoPad(prkKey),
        'Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k',
      );
      final keyInfo = [
        ...utf8.encode('WebPush: info'),
        0,
        ...uaPublic,
        ...sender.publicBytes,
      ];
      final ikm = hkdfExpand(prkKey, keyInfo, 32);
      expect(
        base64UrlNoPad(ikm),
        'S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg',
      );
      final prk = hkdfExtract(salt, ikm);
      expect(
        base64UrlNoPad(prk),
        '09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc',
      );
      final cek = hkdfExpand(
        prk,
        b64('Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA'),
        16,
      );
      expect(base64UrlNoPad(cek), 'oIhVW04MRdy2XN9CiKLxTg');
      final nonce = hkdfExpand(
        prk,
        b64('Q29udGVudC1FbmNvZGluZzogbm9uY2UA'),
        12,
      );
      expect(base64UrlNoPad(nonce), '4h_95klXJ5E_qnoN');
    });

    test('the whole message, byte for byte', () {
      final body = encryptWebPush(
        uaPublic: uaPublic,
        authSecret: authSecret,
        plaintext: utf8.encode('When I grow up, I want to be a watermelon'),
        senderKeys: sender,
        salt: salt,
      );
      // The RFC says 145, but its body is 144 bytes: 86 of header + 41 + 1 + 16.
      // La RFC annonce 145, mais son corps fait 144 octets.
      expect(body, hasLength(144));
      expect(
        base64UrlNoPad(body),
        'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml'
        'mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT'
        'pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
      );
    });

    test('random keys and salt by default: two messages differ', () {
      List<int> once() => encryptWebPush(
        uaPublic: uaPublic,
        authSecret: authSecret,
        plaintext: utf8.encode('Bonjour'),
      );
      expect(once(), isNot(equals(once())));
    });

    test('bad inputs refused', () {
      expect(
        () => encryptWebPush(
          uaPublic: uaPublic.sublist(1),
          authSecret: authSecret,
          plaintext: const [1],
        ),
        throwsFormatException,
      );
      expect(
        () => encryptWebPush(
          uaPublic: uaPublic,
          authSecret: authSecret.sublist(1),
          plaintext: const [1],
        ),
        throwsFormatException,
      );
      final notOnCurve = Uint8List.fromList(uaPublic)..[64] ^= 1;
      expect(() => decodeP256PublicKey(notOnCurve), throwsA(anything));
      expect(
        () => encryptWebPush(
          uaPublic: uaPublic,
          authSecret: authSecret,
          plaintext: Uint8List(maxPushPlaintext + 1),
        ),
        throwsArgumentError,
      );
      expect(
        encryptWebPush(
          uaPublic: uaPublic,
          authSecret: authSecret,
          plaintext: Uint8List(maxPushPlaintext),
        ),
        hasLength(recordSize),
      );
      expect(
        () => P256KeyPair.fromPrivate(Uint8List(32)),
        throwsFormatException,
      );
    });
  });

  group('VAPID (RFC 8292)', () {
    final now = DateTime.utc(2026, 11, 2, 12);
    final endpoint = Uri.parse(
      'https://updates.push.services.mozilla.com/wpush/v2/abc',
    );

    test('file round trip keeps the same key', () {
      final keys = VapidKeys.generate();
      final again = VapidKeys.parse(keys.fileContents);
      expect(again.publicKey, keys.publicKey);
      expect(b64(keys.publicKey), hasLength(p256PublicKeyLength));
      expect(() => VapidKeys.parse('pas une clé'), throwsFormatException);
    });

    test('secret file created once, never overwritten', () async {
      final dir = await Directory.systemTemp.createTemp('vapid');
      addTearDown(() => dir.delete(recursive: true));
      final path = '${dir.path}/vapid_private_key';
      final publicKey = await generateVapidFile(path);
      String stored() =>
          VapidKeys.parse(File(path).readAsStringSync()).publicKey;
      expect(stored(), publicKey);
      await expectLater(
        generateVapidFile(path),
        throwsA(isA<FileSystemException>()),
      );
      expect(stored(), publicKey);
    });

    test('token claims and a valid ES256 signature', () {
      final keys = VapidKeys.generate();
      final token = keys.token(endpoint, 'mailto:contact@example.org', now);
      final [header, claims, signature] = token.split('.');
      expect(jsonDecode(utf8.decode(b64(header))), {
        'typ': 'JWT',
        'alg': 'ES256',
      });
      expect(jsonDecode(utf8.decode(b64(claims))), {
        'aud': 'https://updates.push.services.mozilla.com',
        'exp':
            now.add(const Duration(hours: 12)).millisecondsSinceEpoch ~/ 1000,
        'sub': 'mailto:contact@example.org',
      });
      final raw = b64(signature);
      expect(raw, hasLength(64));
      BigInt big(List<int> bytes) =>
          bytes.fold(BigInt.zero, (v, b) => (v << 8) | BigInt.from(b));
      final verifier = ECDSASigner(SHA256Digest())
        ..init(false, PublicKeyParameter<ECPublicKey>(keys.pair.publicKey));
      expect(
        verifier.verifySignature(
          Uint8List.fromList(utf8.encode('$header.$claims')),
          ECSignature(big(raw.sublist(0, 32)), big(raw.sublist(32))),
        ),
        isTrue,
      );
      expect(
        keys.authorization(endpoint, 'mailto:contact@example.org', now),
        'vapid t=$token, k=${keys.publicKey}',
      );
    });
  });
}

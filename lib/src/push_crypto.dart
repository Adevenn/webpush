import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

// Web Push message encryption (RFC 8291) over the aes128gcm content coding
// (RFC 8188), on pointycastle. One record only: a push message is small.
// Chiffrement des messages Web Push (RFC 8291) avec le codage aes128gcm
// (RFC 8188), sur pointycastle. Un seul enregistrement : un message
// push est petit.

/// Record size written in the header (RFC 8291 §4: 4096 is the usual one).
/// Taille d'enregistrement écrite dans l'en-tête (RFC 8291 §4 : 4096 d'usage).
const recordSize = 4096;

const _saltLength = 16;
const _keyLength = 16;
const _nonceLength = 12;
const _tagLength = 16;
const _sha256Length = 32;
const _p256CoordinateLength = 32;

/// Uncompressed P-256 point: 0x04, then x and y (65 bytes).
/// Point P-256 non compressé : 0x04, puis x et y (65 octets).
const p256PublicKeyLength = 1 + 2 * _p256CoordinateLength;
const _authSecretLength = 16;

/// Padding delimiter of the last (and only) record (RFC 8188 §2).
/// Délimiteur de bourrage du dernier (et seul) enregistrement (RFC 8188 §2).
const _lastRecordDelimiter = 0x02;

/// Header: salt (16), record size (4), key id length (1), key id (65).
/// En-tête : sel (16), taille d'enregistrement (4), longueur de l'id (1), id (65).
const _webPushHeaderLength = _saltLength + 4 + 1 + p256PublicKeyLength;

/// Largest plaintext that fits one record (4096 − 16 − 1) and is accepted by
/// every push service (they take 4096 bytes of body; the header uses 86).
/// Plus grand texte clair qui tient dans un enregistrement et que tous les
/// services push acceptent (corps de 4096 octets ; l'en-tête en prend 86).
const maxPushPlaintext = recordSize - _webPushHeaderLength - _tagLength - 1;

final _p256 = ECCurve_secp256r1();

Uint8List _bytes(String text) => Uint8List.fromList(utf8.encode(text));

Uint8List _concat(List<List<int>> parts) =>
    Uint8List.fromList([for (final part in parts) ...part]);

/// Base64url without padding (RFC 4648 §5), as Web Push uses it.
/// Base64url sans remplissage (RFC 4648 §5), comme Web Push l'emploie.
String base64UrlNoPad(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Reads base64url with or without padding; spaces are ignored.
/// Lit du base64url avec ou sans remplissage ; les espaces sont ignorés.
Uint8List decodeBase64Url(String text) {
  final clean = text.replaceAll(RegExp(r'\s'), '').replaceAll('=', '');
  return base64Url.decode(clean.padRight((clean.length + 3) ~/ 4 * 4, '='));
}

Uint8List _hmacSha256(List<int> key, List<int> data) {
  final mac = HMac(SHA256Digest(), 64)
    ..init(KeyParameter(Uint8List.fromList(key)));
  return mac.process(Uint8List.fromList(data));
}

/// HKDF-Extract with SHA-256 (RFC 5869 §2.2).
Uint8List hkdfExtract(List<int> salt, List<int> ikm) => _hmacSha256(salt, ikm);

/// HKDF-Expand with SHA-256, one block only (at most 32 bytes, enough here).
/// HKDF-Expand avec SHA-256, un seul bloc (32 octets au plus, assez ici).
Uint8List hkdfExpand(List<int> prk, List<int> info, int length) {
  if (length < 1 || length > _sha256Length) {
    throw ArgumentError.value(length, 'length', 'must be 1..$_sha256Length');
  }
  return Uint8List.sublistView(_hmacSha256(prk, [...info, 1]), 0, length);
}

/// A P-256 key pair; [publicKey] is the uncompressed point.
/// Une paire de clés P-256 ; [publicKey] est le point non compressé.
class P256KeyPair {
  P256KeyPair._(this.privateKey, this.publicKey);

  /// From the 32-byte private scalar / À partir du scalaire privé de 32 octets.
  factory P256KeyPair.fromPrivate(List<int> privateBytes) {
    if (privateBytes.length != _p256CoordinateLength) {
      throw const FormatException('A P-256 private key is 32 bytes');
    }
    final d = _toBigInt(privateBytes);
    if (d == BigInt.zero || d >= _p256.n) {
      throw const FormatException('P-256 private key out of range');
    }
    final q = (_p256.G * d)!;
    return P256KeyPair._(ECPrivateKey(d, _p256), ECPublicKey(q, _p256));
  }

  /// A fresh random pair / Une nouvelle paire au hasard.
  factory P256KeyPair.generate([Random? random]) {
    final generator = ECKeyGenerator()
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(_p256),
          _secureRandom(random ?? Random.secure()),
        ),
      );
    final pair = generator.generateKeyPair();
    return P256KeyPair._(pair.privateKey, pair.publicKey);
  }

  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  Uint8List get privateBytes =>
      _fromBigInt(privateKey.d!, _p256CoordinateLength);

  Uint8List get publicBytes => publicKey.Q!.getEncoded(false);
}

/// Reads an uncompressed P-256 public key (65 bytes, a point on the curve).
/// Lit une clé publique P-256 non compressée (65 octets, un point de la courbe).
ECPublicKey decodeP256PublicKey(List<int> bytes) {
  if (bytes.length != p256PublicKeyLength || bytes.first != 0x04) {
    throw const FormatException('Not an uncompressed P-256 public key');
  }
  final point = _p256.curve.decodePoint(bytes);
  if (point == null || point.isInfinity || !_onCurve(point)) {
    throw const FormatException('Not a P-256 point');
  }
  return ECPublicKey(point, _p256);
}

/// y² = x³ + ax + b: decodePoint alone does not check it.
/// y² = x³ + ax + b : decodePoint seul ne le vérifie pas.
bool _onCurve(ECPoint point) {
  final x = point.x!;
  final curve = _p256.curve;
  final rhs = x * x * x + curve.a! * x + curve.b!;
  return point.y!.square().toBigInteger() == rhs.toBigInteger();
}

SecureRandom _secureRandom(Random seed) {
  const seedLength = 32;
  return FortunaRandom()..seed(
    KeyParameter(
      Uint8List.fromList([
        for (var i = 0; i < seedLength; i++) seed.nextInt(256),
      ]),
    ),
  );
}

BigInt _toBigInt(List<int> bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _fromBigInt(BigInt value, int length) {
  final out = Uint8List(length);
  var rest = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (rest & BigInt.from(0xff)).toInt();
    rest >>= 8;
  }
  return out;
}

/// ECDH on P-256: the x coordinate of the shared point, 32 bytes.
/// ECDH sur P-256 : la coordonnée x du point partagé, 32 octets.
Uint8List ecdhP256(ECPrivateKey private, ECPublicKey public) {
  final agreement = ECDHBasicAgreement()..init(private);
  return _fromBigInt(
    agreement.calculateAgreement(public),
    _p256CoordinateLength,
  );
}

Uint8List _aesGcm(Uint8List key, Uint8List nonce, Uint8List plaintext) {
  final cipher = GCMBlockCipher(AESEngine())
    ..init(
      true,
      AEADParameters(KeyParameter(key), _tagLength * 8, nonce, Uint8List(0)),
    );
  return cipher.process(plaintext);
}

/// One aes128gcm body (RFC 8188 §2) holding a single, last record.
/// Un corps aes128gcm (RFC 8188 §2) d'un seul enregistrement, le dernier.
Uint8List encryptAes128gcm({
  required List<int> ikm,
  required List<int> salt,
  required List<int> plaintext,
  List<int> keyId = const [],
  int rs = recordSize,
}) {
  if (salt.length != _saltLength) {
    throw ArgumentError.value(salt.length, 'salt', 'must be 16 bytes');
  }
  if (plaintext.length + 1 + _tagLength > rs) {
    throw ArgumentError.value(plaintext.length, 'plaintext', 'too long');
  }
  if (keyId.length > 255) {
    throw ArgumentError.value(keyId.length, 'keyId', 'at most 255 bytes');
  }
  final prk = hkdfExtract(salt, ikm);
  final cek = hkdfExpand(prk, [
    ..._bytes('Content-Encoding: aes128gcm'),
    0,
  ], _keyLength);
  final nonce = hkdfExpand(prk, [
    ..._bytes('Content-Encoding: nonce'),
    0,
  ], _nonceLength);
  final header = ByteData(_saltLength + 4 + 1)..setUint32(_saltLength, rs);
  final headerBytes = header.buffer.asUint8List()
    ..setRange(0, _saltLength, salt)
    ..[_saltLength + 4] = keyId.length;
  return _concat([
    headerBytes,
    keyId,
    _aesGcm(
      cek,
      nonce,
      _concat([
        plaintext,
        [_lastRecordDelimiter],
      ]),
    ),
  ]);
}

/// Encrypts [plaintext] for one browser subscription (RFC 8291 §3.4).
/// [senderKeys] and [salt] are random unless given (tests use RFC 8291 §5).
/// Chiffre [plaintext] pour un abonnement de navigateur (RFC 8291 §3.4).
/// [senderKeys] et [salt] sont aléatoires sauf s'ils sont donnés (les tests
/// reprennent la RFC 8291 §5).
Uint8List encryptWebPush({
  required List<int> uaPublic,
  required List<int> authSecret,
  required List<int> plaintext,
  P256KeyPair? senderKeys,
  List<int>? salt,
}) {
  if (authSecret.length != _authSecretLength) {
    throw const FormatException('The auth secret is 16 bytes');
  }
  if (plaintext.length > maxPushPlaintext) {
    throw ArgumentError.value(plaintext.length, 'plaintext', 'too long');
  }
  final ua = decodeP256PublicKey(uaPublic);
  final sender = senderKeys ?? P256KeyPair.generate();
  final random = Random.secure();
  final actualSalt =
      salt ?? [for (var i = 0; i < _saltLength; i++) random.nextInt(256)];
  final asPublic = sender.publicBytes;
  final ecdhSecret = ecdhP256(sender.privateKey, ua);
  final prkKey = hkdfExtract(authSecret, ecdhSecret);
  final keyInfo = _concat([
    _bytes('WebPush: info'),
    [0],
    uaPublic,
    asPublic,
  ]);
  final ikm = hkdfExpand(prkKey, keyInfo, _sha256Length);
  return encryptAes128gcm(
    ikm: ikm,
    salt: actualSalt,
    plaintext: plaintext,
    keyId: asPublic,
  );
}

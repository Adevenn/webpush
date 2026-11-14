import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'push_crypto.dart';

// VAPID (RFC 8292): the sender signs a short-lived ES256 token for each push
// service, so that only it can push to its subscriptions.
// VAPID (RFC 8292) : l'expéditeur signe un jeton ES256 de courte durée pour
// chaque service push, pour être le seul à pousser vers ses abonnements.

/// Token lifetime: 12 h, under the 24 h that RFC 8292 §2 allows.
/// Durée du jeton : 12 h, sous les 24 h que la RFC 8292 §2 permet.
const vapidTokenLifetime = Duration(hours: 12);

const _coordinateLength = 32;

/// The sender's VAPID key pair, read from its secret file: one line, the
/// 32-byte private key in base64url. The public key is derived from it.
/// La paire de clés VAPID de l'expéditeur, lue dans son fichier secret : une
/// ligne, la clé privée de 32 octets en base64url. La clé publique en découle.
class VapidKeys {
  VapidKeys(this.pair);

  /// Throws [FormatException] for a malformed file.
  /// Lève [FormatException] pour un fichier mal formé.
  factory VapidKeys.parse(String fileContents) =>
      VapidKeys(P256KeyPair.fromPrivate(decodeBase64Url(fileContents.trim())));

  factory VapidKeys.generate() => VapidKeys(P256KeyPair.generate());

  final P256KeyPair pair;

  /// Contents of the secret file / Contenu du fichier secret.
  String get fileContents => '${base64UrlNoPad(pair.privateBytes)}\n';

  /// Public key for `PushManager.subscribe` (applicationServerKey).
  /// Clé publique pour `PushManager.subscribe` (applicationServerKey).
  String get publicKey => base64UrlNoPad(pair.publicBytes);

  /// `Authorization` header for [endpoint] (RFC 8292 §3): `vapid t=…, k=…`.
  /// [subject] is a `mailto:` or `https:` contact for the push service.
  /// En-tête `Authorization` pour [endpoint] (RFC 8292 §3). [subject] est un
  /// contact `mailto:` ou `https:` pour le service push.
  String authorization(Uri endpoint, String subject, DateTime now) =>
      'vapid t=${token(endpoint, subject, now)}, k=$publicKey';

  /// The signed JWT (ES256) / Le JWT signé (ES256).
  String token(Uri endpoint, String subject, DateTime now) {
    final header = {'typ': 'JWT', 'alg': 'ES256'};
    final expiry = now.add(vapidTokenLifetime);
    final claims = {
      'aud': endpoint.origin,
      'exp': expiry.millisecondsSinceEpoch ~/ Duration.millisecondsPerSecond,
      'sub': subject,
    };
    final signingInput =
        '${_segment(jsonEncode(header))}.${_segment(jsonEncode(claims))}';
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
      ..init(true, PrivateKeyParameter<ECPrivateKey>(pair.privateKey));
    final signature = signer.generateSignature(
      Uint8List.fromList(utf8.encode(signingInput)),
    ) as ECSignature;
    final raw = Uint8List(2 * _coordinateLength)
      ..setAll(0, _fixed(signature.r))
      ..setAll(_coordinateLength, _fixed(signature.s));
    return '$signingInput.${base64UrlNoPad(raw)}';
  }

  static String _segment(String json) => base64UrlNoPad(utf8.encode(json));

  static List<int> _fixed(BigInt value) {
    final out = Uint8List(_coordinateLength);
    var rest = value;
    for (var i = _coordinateLength - 1; i >= 0; i--) {
      out[i] = (rest & BigInt.from(0xff)).toInt();
      rest >>= 8;
    }
    return out;
  }
}

/// Creates the VAPID secret file at [path] (never overwrites one) and
/// returns the public key. Meant to run at deploy inside a 700 folder; the
/// installer then makes the file read-only for its owner (400). A file left
/// half written is removed.
/// Crée le fichier secret VAPID à [path] (n'en écrase jamais un) et rend la
/// clé publique. Prévu pour le déploiement, dans un dossier 700 ;
/// l'installateur passe ensuite le fichier en 400. Un fichier à moitié écrit
/// est retiré.
Future<String> generateVapidFile(String path) async {
  final keys = VapidKeys.generate();
  // Exclusive: fails when the file exists, so a key is never replaced.
  // Exclusif : échoue si le fichier existe, une clé n'est jamais remplacée.
  final file = await File(path).create(exclusive: true);
  try {
    await file.writeAsString(keys.fileContents, flush: true);
  } on Object {
    await file.delete();
    rethrow;
  }
  return keys.publicKey;
}

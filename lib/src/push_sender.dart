import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'address_policy.dart';
import 'push_crypto.dart';
import 'pinned_http_client.dart';
import 'vapid.dart';

/// Default push services: Apple's (home-screen apps on iPhone and iPad) and
/// Mozilla's (Firefox on PC). An endpoint is given by the browser, so
/// anything else is refused (no request to arbitrary hosts).
/// Services push par défaut : celui d'Apple (apps de l'écran d'accueil sur
/// iPhone et iPad) et celui de Mozilla (Firefox sur PC). Un endpoint vient
/// du navigateur : tout le reste est refusé.
const pushHostSuffixes = ['.push.apple.com'];
const pushHosts = {'updates.push.services.mozilla.com'};

const Duration pushTimeout = Duration(seconds: 10);
const int _httpsPort = 443;

/// Longest TTL asked of a push service (one day).
/// Plus long TTL demandé à un service push (un jour).
const Duration maxPushTtl = Duration(days: 1);

/// True for an https endpoint of a known push service, on port 443.
/// Vrai pour un endpoint https d'un service push connu, sur le port 443.
bool isAllowedPushEndpoint(Uri endpoint) {
  if (endpoint.scheme != 'https' ||
      endpoint.userInfo.isNotEmpty ||
      endpoint.port != _httpsPort) {
    return false;
  }
  final host = endpoint.host.toLowerCase();
  return pushHosts.contains(host) ||
      pushHostSuffixes.any((suffix) => host.endsWith(suffix));
}

/// One browser's subscription (`PushSubscription.toJSON()` in the browser).
/// L'abonnement d'un navigateur (`PushSubscription.toJSON()` côté navigateur).
class PushSubscription {
  const PushSubscription({
    required this.id,
    required this.userId,
    required this.endpoint,
    required this.p256dh,
    required this.auth,
  });

  final String id;
  final String userId;
  final String endpoint;
  final String p256dh;
  final String auth;
}

/// What the app's service worker shows, sent as JSON.
/// Ce qu'affiche le service worker de l'app, envoyé en JSON.
class PushMessage {
  const PushMessage({
    required this.title,
    required this.body,
    required this.tag,
    this.tab,
  });

  final String title;
  final String body;

  /// Same tag = replaces the previous notification on the device.
  /// Même étiquette = remplace la notification précédente sur l'appareil.
  final String tag;

  /// App tab to open on a tap (« planning »), null for the app as it was.
  /// Onglet de l'app à ouvrir au toucher (« planning »), null sinon.
  final String? tab;

  List<int> encode() => utf8.encode(
    jsonEncode({'title': title, 'body': body, 'tag': tag, 'tab': ?tab}),
  );
}

enum PushOutcome {
  delivered,

  /// 404 or 410: the subscription is gone and must be removed (RFC 8030 §7.3).
  /// 404 ou 410 : l'abonnement a disparu et doit être retiré (RFC 8030 §7.3).
  gone,

  /// Endpoint not allowed or keys unreadable: also to remove.
  /// Endpoint refusé ou clés illisibles : à retirer aussi.
  invalid,

  /// Network trouble or another status: the caller may try again later.
  /// Souci de réseau ou autre statut : l'appelant peut réessayer plus tard.
  failed,
}

/// Sends the encrypted body to the endpoint and returns the HTTP status.
/// Envoie le corps chiffré à l'endpoint et rend le statut HTTP.
typedef PushTransport = Future<int> Function(
  Uri endpoint,
  Map<String, String> headers,
  List<int> body,
);

/// Encrypts and sends Web Push messages, signed with the sender's VAPID key.
/// Chiffre et envoie les messages Web Push, signés par la clé VAPID de
/// l'expéditeur.
class PushSender {
  PushSender({
    required this.keys,
    required this.subject,
    PushTransport? transport,
    DateTime Function()? clock,
  }) : _transport = transport ?? safePushTransport,
       _clock = clock ?? DateTime.now;

  final VapidKeys keys;

  /// `mailto:` contact given to the push services (RFC 8292 §2.1).
  /// Contact `mailto:` donné aux services push (RFC 8292 §2.1).
  final String subject;
  final PushTransport _transport;
  final DateTime Function() _clock;

  Future<PushOutcome> send(
    PushSubscription subscription,
    PushMessage message, {
    required Duration ttl,
    bool urgent = false,
  }) async {
    final endpoint = Uri.tryParse(subscription.endpoint);
    if (endpoint == null || !isAllowedPushEndpoint(endpoint)) {
      return PushOutcome.invalid;
    }
    final List<int> body;
    try {
      body = encryptWebPush(
        uaPublic: decodeBase64Url(subscription.p256dh),
        authSecret: decodeBase64Url(subscription.auth),
        plaintext: message.encode(),
      );
    } on FormatException {
      return PushOutcome.invalid;
    }
    final seconds = ttl.isNegative
        ? 0
        : (ttl > maxPushTtl ? maxPushTtl : ttl).inSeconds;
    try {
      final status = await _transport(endpoint, {
        HttpHeaders.authorizationHeader: keys.authorization(
          endpoint,
          subject,
          _clock(),
        ),
        'ttl': '$seconds',
        'urgency': urgent ? 'high' : 'normal',
        'content-encoding': 'aes128gcm',
        HttpHeaders.contentTypeHeader: 'application/octet-stream',
      }, body);
      if (status >= 200 && status < 300) return PushOutcome.delivered;
      if (status == HttpStatus.notFound || status == HttpStatus.gone) {
        return PushOutcome.gone;
      }
      return PushOutcome.failed;
    } on Exception {
      return PushOutcome.failed;
    }
  }
}

/// The real transport: the name is resolved here, every address must be
/// public, and the connection goes to the checked address (as SafeFetcher).
/// Le vrai transport : le nom est résolu ici, chaque adresse doit être
/// publique, et la connexion va vers l'adresse vérifiée (comme SafeFetcher).
Future<int> safePushTransport(
  Uri endpoint,
  Map<String, String> headers,
  List<int> body,
) async {
  final addresses = await InternetAddress.lookup(endpoint.host);
  if (addresses.isEmpty || !addresses.every(isPublicAddress)) {
    throw const SocketException('push service address refused');
  }
  final client = pinnedHttpClient(addresses.first, pushTimeout);
  try {
    final request = await client.postUrl(endpoint).timeout(pushTimeout);
    request
      ..followRedirects = false
      ..persistentConnection = false
      ..contentLength = body.length;
    headers.forEach(request.headers.set);
    request.add(body);
    final response = await request.close().timeout(pushTimeout);
    await response.drain<void>().catchError((_) {});
    return response.statusCode;
  } finally {
    client.close(force: true);
  }
}

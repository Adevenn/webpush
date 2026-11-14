# webpush

Envoi de notifications **Web Push** en Dart pur (sans Flutter), partagé par Puffin et Meerkat.
Extrait à l'identique du worker de Puffin : les octets envoyés par défaut sont les mêmes (test `same_bytes_test.dart`).

## Ce que fait le paquet

- **Chiffrement** RFC 8291 sur le codage `aes128gcm` de la RFC 8188, en un seul enregistrement de 4096 octets. Texte clair limité à `maxPushPlaintext` (3993 octets).
- **VAPID** RFC 8292 : jeton ES256 de 12 h, signé à chaque envoi. La clé privée vit dans un fichier créé une seule fois (`generateVapidFile`), jamais remplacé.
- **Liste fermée de services push** : par défaut `*.push.apple.com` et `updates.push.services.mozilla.com`, en HTTPS sur le port 443. Tout autre endpoint est refusé sans requête.
- **Adresse vérifiée et épinglée** : le nom du service est résolu, chaque adresse doit être publique (`isPublicAddress`), puis la connexion va à l'adresse vérifiée (`pinnedHttpClient`), avec la vérification TLS sur le nom.
- **Résultat** (`PushOutcome`) :
  - `delivered` : envoyé ;
  - `gone` : 404 ou 410, l'abonnement a disparu, l'appelant le retire ;
  - `invalid` : endpoint refusé ou clés illisibles, à retirer aussi ;
  - `failed` : réseau ou autre statut, l'appelant peut réessayer.

## Utilisation

Dans le `pubspec.yaml` de l'application, dépendance git figée sur un commit (SHA complet du tag voulu) :

```yaml
dependencies:
  webpush:
    git:
      url: https://github.com/<compte>/webpush.git
      ref: <sha complet du tag v1.0.0>
```

```dart
import 'package:webpush/webpush.dart';

final sender = PushSender(
  keys: VapidKeys.parse(await File(cheminCle).readAsString()),
  subject: 'mailto:contact@example.org',
);
final outcome = await sender.send(
  subscription,                         // PushSubscription du navigateur
  const PushMessage(title: 'Titre', body: 'Texte', tag: 'source:cle'),
  ttl: const Duration(hours: 12),
  urgency: PushUrgency.low,             // ou urgent: true (high) ; défaut normal
);
if (outcome == PushOutcome.gone) {
  // Retirer l'abonnement.
}
```

Autre liste de services : `PushSender(..., services: const PushServices(hosts: {...}, hostSuffixes: ['.exemple.net']))`. Une fin de nom doit commencer par un point, sinon elle est ignorée.

## En-têtes envoyés

`Authorization: vapid t=…, k=…`, `TTL` (borné de 0 à 1 jour), `Urgency`, `Content-Encoding: aes128gcm`, `Content-Type: application/octet-stream`.

## Développement

```
dart pub get
dart analyze
dart test
```

`test/fixtures/puffin_reference.json` est la référence figée des octets de Puffin (produite une fois par `tool/puffin_reference/make_reference.dart`). **Ne jamais la régénérer pour faire passer un test.**

## Licence

[MPL-2.0](LICENSE).

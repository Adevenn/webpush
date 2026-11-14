import 'dart:io';a

/// An address block: first bytes and prefix length in bits.
/// Un bloc d'adresses : premiers octets et longueur du préfixe en bits.
class _Block {
  const _Block(this.prefix, this.bits);

  final List<int> prefix;
  final int bits;

  bool contains(List<int> bytes) {
    var left = bits;
    for (var i = 0; left > 0; i++) {
      final take = left >= 8 ? 8 : left;
      final mask = (0xFF << (8 - take)) & 0xFF;
      if ((bytes[i] & mask) != (prefix[i] & mask)) return false;
      left -= take;
    }
    return true;
  }
}

// IPv4 blocks never fetched (IANA special-purpose registry, RFC 6890).
// Blocs IPv4 jamais récupérés (registre IANA des usages spéciaux, RFC 6890).
const _blockedV4 = [
  _Block([0], 8), // "this network" / « ce réseau »
  _Block([10], 8), // private / privé
  _Block([100, 64], 10), // CGNAT, Tailscale
  _Block([127], 8), // loopback / bouclage
  _Block([169, 254], 16), // link-local (cloud metadata) / lien local
  _Block([172, 16], 12), // private / privé
  _Block([192, 0, 0], 24), // IETF protocol assignments
  _Block([192, 0, 2], 24), // documentation
  _Block([192, 88, 99], 24), // 6to4 relay / relais 6to4
  _Block([192, 168], 16), // private / privé
  _Block([198, 18], 15), // benchmarking / tests de performance
  _Block([198, 51, 100], 24), // documentation
  _Block([203, 0, 113], 24), // documentation
  _Block([224], 4), // multicast
  _Block([240], 4), // reserved, broadcast / réservé, diffusion
];

// IPv6: only global unicast (2000::/3) is allowed, minus these blocks.
// IPv6 : seule l'unicast globale (2000::/3) est permise, moins ces blocs.
const _globalV6 = _Block([0x20], 3);
const _blockedV6 = [
  _Block([0x20, 0x01, 0x00, 0x00], 32), // Teredo (embeds an IPv4)
  _Block([0x20, 0x01, 0x00, 0x02, 0x00, 0x00], 48), // benchmarking
  _Block([0x20, 0x01, 0x00, 0x10], 28), // ORCHID
  _Block([0x20, 0x01, 0x0d, 0xb8], 32), // documentation
  _Block([0x20, 0x02], 16), // 6to4 (embeds an IPv4)
];

/// Length of an IPv4 address, in bytes.
/// Longueur d'une adresse IPv4, en octets.
const int ipv4Bytes = 4;

/// Bytes before the IPv4 part of an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
/// Octets avant la partie IPv4 d'une adresse IPv6 « mappée » (::ffff:a.b.c.d).
const _mappedPrefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF];

/// True only for a public Internet address: private, loopback, link-local,
/// CGNAT and Tailscale (100.64.0.0/10, fd7a:115c:a1e0::/48), ULA, multicast,
/// documentation and reserved blocks are refused (SSRF).
/// Vrai seulement pour une adresse publique d'Internet : privées, bouclage,
/// lien local, CGNAT et Tailscale, ULA, multicast, documentation et blocs
/// réservés sont refusés (SSRF).
bool isPublicAddress(InternetAddress address) {
  final bytes = address.rawAddress;
  if (address.type == InternetAddressType.IPv4) {
    return !_blockedV4.any((b) => b.contains(bytes));
  }
  if (address.type != InternetAddressType.IPv6) return false;
  final mapped = List.generate(_mappedPrefix.length, (i) => bytes[i]);
  if (_sameBytes(mapped, _mappedPrefix)) {
    // ::ffff:10.0.0.1 is 10.0.0.1: judged as IPv4.
    // ::ffff:10.0.0.1 est 10.0.0.1 : jugée comme une IPv4.
    final v4 = bytes.sublist(bytes.length - ipv4Bytes);
    return !_blockedV4.any((b) => b.contains(v4));
  }
  return _globalV6.contains(bytes) && !_blockedV6.any((b) => b.contains(bytes));
}

bool _sameBytes(List<int> a, List<int> b) {
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

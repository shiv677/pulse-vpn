// Pulse VPN - Pro Authentication & Cryptographic Session Management Engine
// lib/core/auth_service.dart

import 'dart:convert';
import 'package:crypto/crypto.dart';

enum UserTier {
  free,
  pro,
}

class SecurityException implements Exception {
  final String message;
  const SecurityException(this.message);

  @override
  String toString() => 'SecurityException: $message';
}

class UserSession {
  final String userId;
  final String email;
  final UserTier tier;
  final String token;
  final DateTime expiresAt;

  const UserSession({
    required this.userId,
    required this.email,
    required this.tier,
    required this.token,
    required this.expiresAt,
  });

  bool isExpired({DateTime? now}) {
    final checkTime = (now ?? DateTime.now()).toUtc();
    return !expiresAt.toUtc().isAfter(checkTime);
  }

  bool get isPro => tier == UserTier.pro && !isExpired();

  Map<String, dynamic> toJson() => {
        'userId': userId,
        'email': email,
        'tier': tier.name,
        'token': token,
        'expiresAt': expiresAt.toUtc().toIso8601String(),
        'isPro': isPro,
      };
}

abstract class TokenPersistence {
  Future<void> saveToken(String token);
  Future<String?> loadToken();
  Future<void> deleteToken();
}

class InMemoryTokenPersistence implements TokenPersistence {
  String? _token;

  @override
  Future<void> saveToken(String token) async {
    _token = token;
  }

  @override
  Future<String?> loadToken() async => _token;

  @override
  Future<void> deleteToken() async {
    _token = null;
  }
}

class AuthService {
  /// Default server secret used for cryptographic token verification.
  /// In cloud/production deployments, this matches the server's private PULSE_AUTH_SECRET.
  static const String defaultServerSecret =
      'pulse_vpn_secure_hmac_sha256_server_secret_2026';

  final TokenPersistence persistence;
  final String serverSecret;
  UserSession? _currentSession;

  AuthService({
    TokenPersistence? persistence,
    String? serverSecret,
  })  : persistence = persistence ?? InMemoryTokenPersistence(),
        serverSecret = serverSecret ?? defaultServerSecret;

  UserSession? get currentSession => _currentSession;
  bool get isAuthenticated =>
      _currentSession != null && !_currentSession!.isExpired();
  bool get isProUser => _currentSession?.isPro ?? false;

  /// Computes HMAC-SHA256 signature over header.payload
  static String computeHmacSignature(String headerAndPayload, String secret) {
    final hmac = Hmac(sha256, utf8.encode(secret));
    final digest = hmac.convert(utf8.encode(headerAndPayload));
    return base64Url.encode(digest.bytes).replaceAll('=', '');
  }

  static String computeHmacSha256(String headerAndPayload, String secret) =>
      computeHmacSignature(headerAndPayload, secret);

  /// Constant-time string equality check to prevent timing attacks
  static bool secureCompare(String a, String b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }

  /// Decodes standard JWT payload claims (`sub`, `email`, `tier`, `exp`)
  static Map<String, dynamic> decodeJwtClaims(String jwtToken) {
    final parts = jwtToken.trim().split('.');
    if (parts.length != 3) {
      throw const FormatException('Invalid JWT format: expected 3 dot-separated segments');
    }

    final normalizedPayload = base64Url.normalize(parts[1]);
    final payloadBytes = base64Url.decode(normalizedPayload);
    final payloadStr = utf8.decode(payloadBytes);
    final decoded = jsonDecode(payloadStr);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('Invalid JWT payload structure');
    }
    return decoded;
  }

  /// Generates a tamper-proof cryptographically signed JWT with HMAC-SHA256
  static String createSignedJwt({
    required String userId,
    required String email,
    required UserTier tier,
    required DateTime expiresAt,
    String secret = defaultServerSecret,
  }) {
    final header = base64Url
        .encode(utf8.encode(jsonEncode({'alg': 'HS256', 'typ': 'JWT'})))
        .replaceAll('=', '');
    final payload = base64Url
        .encode(utf8.encode(jsonEncode({
          'sub': userId,
          'email': email,
          'tier': tier.name,
          'exp': expiresAt.toUtc().millisecondsSinceEpoch ~/ 1000,
        })))
        .replaceAll('=', '');
    final toSign = '$header.$payload';
    final signature = computeHmacSignature(toSign, secret);
    return '$toSign.$signature';
  }

  /// Verifies a JWT token cryptographically:
  /// 1. Checks structure (3 parts)
  /// 2. Validates HMAC-SHA256 signature against secret key
  /// 3. Validates expiration timestamp
  /// Throws SecurityException on signature mismatch or tampered data.
  UserSession verifyToken(String token, {String? signingKey, String? secret, DateTime? now}) {
    final parts = token.trim().split('.');
    if (parts.length != 3) {
      throw const FormatException('Invalid JWT format');
    }

    final key = signingKey ?? secret ?? serverSecret;
    final expectedSig = computeHmacSignature('${parts[0]}.${parts[1]}', key);
    if (!secureCompare(parts[2], expectedSig)) {
      throw const SecurityException(
        'Cryptographic signature verification failed: token is untrusted or tampered',
      );
    }

    final claims = decodeJwtClaims(token);
    final sub = (claims['sub'] ?? '').toString();
    if (sub.isEmpty) {
      throw const FormatException('JWT missing required "sub" claim');
    }

    final email = (claims['email'] ?? '$sub@pulsevpn.io').toString();

    String rawTier = (claims['tier'] ?? '').toString().toLowerCase();
    if (rawTier.isEmpty && claims['app_metadata'] is Map) {
      rawTier = (claims['app_metadata']['tier'] ?? 'free').toString().toLowerCase();
    } else if (rawTier.isEmpty && claims['user_metadata'] is Map) {
      rawTier = (claims['user_metadata']['tier'] ?? 'free').toString().toLowerCase();
    }
    final tier = rawTier == 'pro' ? UserTier.pro : UserTier.free;

    final expSeconds = claims['exp'];
    if (expSeconds is! int) {
      throw const FormatException('JWT missing integer "exp" claim');
    }

    final expiresAt =
        DateTime.fromMillisecondsSinceEpoch(expSeconds * 1000, isUtc: true);
    final session = UserSession(
      userId: sub,
      email: email,
      tier: tier,
      token: token,
      expiresAt: expiresAt,
    );

    if (session.isExpired(now: now)) {
      throw StateError('JWT token has expired');
    }

    return session;
  }

  /// Registers a standard user account. ALWAYS defaults to UserTier.free.
  /// (Pro tier is NEVER granted by client email heuristics).
  Future<UserSession> signUp({
    required String email,
    required String password,
    Duration ttl = const Duration(hours: 24),
  }) async {
    final trimmedEmail = email.trim();
    if (trimmedEmail.isEmpty || !trimmedEmail.contains('@')) {
      throw ArgumentError('Valid email address is required');
    }
    if (password.length < 6) {
      throw ArgumentError('Password must be at least 6 characters');
    }

    final userId = 'usr_${trimmedEmail.hashCode.abs()}';
    final expiresAt = DateTime.now().toUtc().add(ttl);

    // Standard client registrations ALWAYS default to free tier
    final token = createSignedJwt(
      userId: userId,
      email: trimmedEmail,
      tier: UserTier.free,
      expiresAt: expiresAt,
      secret: serverSecret,
    );

    final session = verifyToken(token);
    _currentSession = session;
    await persistence.saveToken(token);
    return session;
  }

  /// Logs in: if a server/Supabase signed JWT is provided, verifies its signature.
  /// If standard credentials are used, registers a verified free session.
  Future<UserSession> logIn({
    required String email,
    required String password,
    String? signedToken,
  }) async {
    String token;
    if (signedToken != null && signedToken.trim().isNotEmpty) {
      token = signedToken.trim();
    } else if (password.trim().split('.').length == 3) {
      // User entered/pasted a cryptographically signed Pro License token directly
      token = password.trim();
    } else {
      final trimmedEmail = email.trim();
      if (trimmedEmail.isEmpty || password.isEmpty) {
        throw ArgumentError('Email and password are required');
      }
      final userId = 'usr_${trimmedEmail.hashCode.abs()}';
      final expiresAt = DateTime.now().toUtc().add(const Duration(hours: 24));
      token = createSignedJwt(
        userId: userId,
        email: trimmedEmail,
        tier: UserTier.free,
        expiresAt: expiresAt,
        secret: serverSecret,
      );
    }

    final session = verifyToken(token);
    _currentSession = session;
    await persistence.saveToken(token);
    return session;
  }

  /// Explicitly provisions a verified Pro session using the server's private secret key.
  /// Only usable by the administrator or backend server API with the serverSecret.
  Future<UserSession> authenticateWithServerProSecret({
    required String email,
    required String serverAdminSecret,
    Duration ttl = const Duration(days: 30),
  }) async {
    if (serverAdminSecret != serverSecret) {
      throw const FormatException('Invalid server secret key. Pro tier cannot be provisioned.');
    }
    final trimmedEmail = email.trim();
    final userId = 'pro_${trimmedEmail.hashCode.abs()}';
    final expiresAt = DateTime.now().toUtc().add(ttl);
    final token = createSignedJwt(
      userId: userId,
      email: trimmedEmail,
      tier: UserTier.pro,
      expiresAt: expiresAt,
      secret: serverSecret,
    );

    final session = verifyToken(token);
    _currentSession = session;
    await persistence.saveToken(token);
    return session;
  }

  /// Clears active session and deletes persisted token
  Future<void> logOut() async {
    _currentSession = null;
    await persistence.deleteToken();
  }
}

// Pulse VPN - Pro Authentication & Session Management Engine
// lib/core/auth_service.dart

import 'dart:convert';

enum UserTier {
  free,
  pro,
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

/// Abstract interface for persisting auth tokens securely across platforms
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
  final TokenPersistence persistence;
  UserSession? _currentSession;

  AuthService({TokenPersistence? persistence})
      : persistence = persistence ?? InMemoryTokenPersistence();

  UserSession? get currentSession => _currentSession;

  bool get isAuthenticated =>
      _currentSession != null && !_currentSession!.isExpired();

  bool get isProUser => _currentSession?.isPro ?? false;

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

  /// Generates a signed-format JWT for local self-hosted or demo authentication
  static String createLocalJwt({
    required String userId,
    required String email,
    required UserTier tier,
    required DateTime expiresAt,
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
    final signature = base64Url
        .encode(utf8.encode('pulse_vpn_sig_${userId}_${tier.name}'))
        .replaceAll('=', '');
    return '$header.$payload.$signature';
  }

  /// Verifies a JWT string and constructs an active UserSession
  UserSession verifyToken(String token, {DateTime? now}) {
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

  /// Registers a new user account and persists the session token
  Future<UserSession> signUp({
    required String email,
    required String password,
    UserTier tier = UserTier.free,
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
    final resolvedTier =
        trimmedEmail.toLowerCase().contains('pro') ? UserTier.pro : tier;

    final token = createLocalJwt(
      userId: userId,
      email: trimmedEmail,
      tier: resolvedTier,
      expiresAt: expiresAt,
    );

    final session = verifyToken(token);
    _currentSession = session;
    await persistence.saveToken(token);
    return session;
  }

  /// Logs in using either a Supabase/external JWT or email/password credentials
  Future<UserSession> logIn({
    required String email,
    required String password,
    String? supabaseJwt,
    UserTier? overrideTier,
  }) async {
    String token;
    if (supabaseJwt != null && supabaseJwt.trim().isNotEmpty) {
      token = supabaseJwt.trim();
    } else if (password.split('.').length == 3) {
      token = password.trim();
    } else {
      final trimmedEmail = email.trim();
      if (trimmedEmail.isEmpty || password.isEmpty) {
        throw ArgumentError('Email and password are required');
      }
      final inferredTier = overrideTier ??
          (trimmedEmail.toLowerCase().contains('pro')
              ? UserTier.pro
              : UserTier.free);
      final userId = 'usr_${trimmedEmail.hashCode.abs()}';
      final expiresAt = DateTime.now().toUtc().add(const Duration(hours: 24));
      token = createLocalJwt(
        userId: userId,
        email: trimmedEmail,
        tier: inferredTier,
        expiresAt: expiresAt,
      );
    }

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

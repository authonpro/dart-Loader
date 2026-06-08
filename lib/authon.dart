/// ╔══════════════════════════════════════════════════════════════════════════════╗
/// ║  Authon Dart SDK — Software Licensing & Authentication                    ║
/// ║  Version: 1.0.0                                                           ║
/// ║  Dependencies: http package                                               ║
/// ║                                                                           ║
/// ║  Website: https://authon.pro                                              ║
/// ║  Docs:    https://authon.pro/docs                                         ║
/// ║  Discord: https://discord.gg/jMZCTKPsmE                                   ║
/// ║  Status:  https://authon.pro/status                                       ║
/// ║  Health:  https://api.authon.pro/health                                   ║
/// ║  GitHub:  https://github.com/authonpro                                    ║
/// ║                                                                           ║
/// ║  pubspec.yaml:                                                            ║
/// ║    dependencies:                                                          ║
/// ║      http: ^1.1.0                                                         ║
/// ║      crypto: ^3.0.0                                                       ║
/// ║                                                                           ║
/// ║  Usage:                                                                   ║
/// ║    import 'package:authon/authon.dart';                                   ║
/// ║    final auth = Authon(appId: 'app-id', apiKey: 'api-key');               ║
/// ║    await auth.init();                                                     ║
/// ║    final result = await auth.login('user', 'pass');                       ║
/// ║    print('Welcome ${auth.username}!');                                    ║
/// ╚══════════════════════════════════════════════════════════════════════════════╝
library authon;

import 'dart:convert';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

/// SDK version string.
const String authonVersion = '1.0.0';

/// Default API endpoint URL.
const String defaultApiUrl = 'https://api.authon.pro/v1';

/// Default HTTP timeout.
const Duration defaultTimeout = Duration(seconds: 15);

// ═══════════════════════════════════════════════════════════════════════════════
// EXCEPTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Exception thrown by the Authon SDK.
class AuthonException implements Exception {
  /// Error message from the API or SDK.
  final String message;

  /// Optional error code.
  final int? code;

  const AuthonException(this.message, {this.code});

  @override
  String toString() => 'AuthonException: $message';
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA CLASSES
// ═══════════════════════════════════════════════════════════════════════════════

/// Session data returned after successful authentication.
class SessionData {
  /// Unique session token.
  final String sessionToken;

  /// Authenticated username.
  final String username;

  /// User's access level (0+).
  final int level;

  /// Subscription plan name.
  final String subscription;

  /// Subscription expiration date (ISO 8601).
  final String expiresAt;

  const SessionData({
    required this.sessionToken,
    required this.username,
    required this.level,
    required this.subscription,
    required this.expiresAt,
  });

  factory SessionData.fromJson(Map<String, dynamic> json) {
    return SessionData(
      sessionToken: json['sessionToken'] ?? '',
      username: json['username'] ?? '',
      level: json['level'] ?? 0,
      subscription: json['subscription'] ?? '',
      expiresAt: json['expiresAt'] ?? '',
    );
  }
}

/// Application info from init().
class AppInfo {
  /// Application name.
  final String name;

  /// Application version.
  final String version;

  /// Whether HWID lock is enabled.
  final bool hwidLock;

  /// Whether hash check is enabled.
  final bool hashCheck;

  const AppInfo({
    required this.name,
    required this.version,
    required this.hwidLock,
    required this.hashCheck,
  });

  factory AppInfo.fromJson(Map<String, dynamic> json) {
    return AppInfo(
      name: json['name'] ?? '',
      version: json['version'] ?? '',
      hwidLock: json['hwidLock'] ?? false,
      hashCheck: json['hashCheck'] ?? false,
    );
  }
}

/// File entry from listFiles.
class FileInfo {
  final String id;
  final String name;
  final int size;
  final int minLevel;

  const FileInfo({
    required this.id,
    required this.name,
    required this.size,
    required this.minLevel,
  });

  factory FileInfo.fromJson(Map<String, dynamic> json) {
    return FileInfo(
      id: json['id'] ?? '',
      name: json['name'] ?? '',
      size: json['size'] ?? 0,
      minLevel: json['minLevel'] ?? 0,
    );
  }
}

/// Online users data.
class OnlineData {
  final int count;
  final List<String> users;

  const OnlineData({required this.count, required this.users});

  factory OnlineData.fromJson(Map<String, dynamic> json) {
    return OnlineData(
      count: json['count'] ?? 0,
      users: List<String>.from(json['users'] ?? []),
    );
  }
}

/// Application statistics.
class StatsData {
  final int totalUsers;
  final int onlineUsers;
  final int totalKeys;
  final String appVersion;

  const StatsData({
    required this.totalUsers,
    required this.onlineUsers,
    required this.totalKeys,
    required this.appVersion,
  });

  factory StatsData.fromJson(Map<String, dynamic> json) {
    return StatsData(
      totalUsers: json['totalUsers'] ?? 0,
      onlineUsers: json['onlineUsers'] ?? 0,
      totalKeys: json['totalKeys'] ?? 0,
      appVersion: json['appVersion'] ?? '',
    );
  }
}

/// Blacklist check result.
class BlacklistData {
  final bool blacklisted;
  final String? reason;

  const BlacklistData({required this.blacklisted, this.reason});

  factory BlacklistData.fromJson(Map<String, dynamic> json) {
    return BlacklistData(
      blacklisted: json['blacklisted'] ?? false,
      reason: json['reason'],
    );
  }
}

/// Referral redemption result.
class ReferralData {
  final String expiresAt;
  final int rewardDays;
  final String message;

  const ReferralData({
    required this.expiresAt,
    required this.rewardDays,
    required this.message,
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT
// ═══════════════════════════════════════════════════════════════════════════════

/// Main Authon SDK client for Dart/Flutter.
///
/// Provides full authentication, licensing, variable storage,
/// file management, and activity logging capabilities.
///
/// ```dart
/// final auth = Authon(appId: 'your-app-id', apiKey: 'your-api-key');
/// await auth.init();
/// final session = await auth.login('username', 'password');
/// print('Level: ${session.level}');
/// ```
class Authon {
  final String _appId;
  final String _apiKey;
  final String _apiUrl;
  final http.Client _client;
  final Duration _timeout;

  // Session state
  /// Current session token. Null if not authenticated.
  String? sessionToken;

  /// Authenticated username.
  String? username;

  /// User's access level.
  int level = 0;

  /// Subscription plan name.
  String? subscription;

  /// Subscription expiration date.
  String? expiresAt;

  // App info
  /// Application name (set after init).
  String? appName;

  /// Application version (set after init).
  String? appVersion;

  /// Whether HWID lock is enabled.
  bool hwidLock = false;

  /// Whether hash check is enabled.
  bool hashCheck = false;

  /// Whether init() was called successfully.
  bool initialized = false;

  /// Whether the client has an active session.
  bool get isAuthenticated => sessionToken != null && sessionToken!.isNotEmpty;

  /// Creates a new Authon client.
  ///
  /// [appId] - Your Application ID from the Authon dashboard.
  /// [apiKey] - Your API Key from the Authon dashboard.
  /// [apiUrl] - Custom API URL (default: https://api.authon.pro/v1).
  /// [timeout] - HTTP request timeout (default: 15s).
  Authon({
    required String appId,
    required String apiKey,
    String apiUrl = defaultApiUrl,
    Duration timeout = defaultTimeout,
  })  : assert(appId.isNotEmpty, 'appId is required'),
        assert(apiKey.isNotEmpty, 'apiKey is required'),
        _appId = appId.trim(),
        _apiKey = apiKey.trim(),
        _apiUrl = apiUrl.replaceAll(RegExp(r'/+$'), ''),
        _client = http.Client(),
        _timeout = timeout;

  /// Disposes the HTTP client.
  void dispose() {
    _client.close();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HWID GENERATION
  // ═══════════════════════════════════════════════════════════════════════════

  /// Generates a hardware ID unique to the current machine.
  ///
  /// Windows: disk serial + computer name.
  /// Linux: /etc/machine-id.
  /// macOS: system_profiler hardware UUID.
  ///
  /// Returns a 32-character lowercase hex MD5 hash.
  static Future<String> getHWID() async {
    String raw = '';

    try {
      if (Platform.isWindows) {
        final result = await Process.run('wmic', ['diskdrive', 'get', 'serialnumber']);
        final lines = (result.stdout as String).split('\n');
        if (lines.length > 1) {
          raw = lines[1].trim();
        }
        raw += Platform.localHostname;
      } else if (Platform.isMacOS) {
        final result = await Process.run('system_profiler', ['SPHardwareDataType']);
        final output = result.stdout as String;
        for (final line in output.split('\n')) {
          if (line.contains('UUID')) {
            final parts = line.split(':');
            if (parts.length >= 2) {
              raw = parts[1].trim();
              break;
            }
          }
        }
        if (raw.isEmpty) raw = Platform.localHostname;
      } else {
        // Linux
        final file = File('/etc/machine-id');
        if (await file.exists()) {
          raw = (await file.readAsString()).trim();
        } else {
          raw = '${Platform.localHostname}${Platform.operatingSystemVersion}';
        }
      }
    } catch (_) {
      raw = '${Platform.localHostname}-fallback';
    }

    if (raw.isEmpty) raw = 'fallback-${Platform.localHostname}';
    return md5.convert(utf8.encode(raw)).toString();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL HTTP
  // ═══════════════════════════════════════════════════════════════════════════

  Future<Map<String, dynamic>> _request(Map<String, dynamic> payload) async {
    payload['appId'] = _appId;
    payload['apiKey'] = _apiKey;

    try {
      final response = await _client
          .post(
            Uri.parse(_apiUrl),
            headers: {
              'Content-Type': 'application/json',
              'User-Agent': 'Authon-Dart-SDK/$authonVersion',
            },
            body: jsonEncode(payload),
          )
          .timeout(_timeout);

      final contentType = response.headers['content-type'] ?? '';
      if (contentType.contains('octet-stream')) {
        return {'success': true, 'binary': response.bodyBytes};
      }

      return jsonDecode(response.body) as Map<String, dynamic>;
    } on SocketException {
      return {'success': false, 'message': 'Connection failed. Check https://authon.pro/status'};
    } on HttpException {
      return {'success': false, 'message': 'HTTP error occurred'};
    } catch (e) {
      return {'success': false, 'message': 'Unexpected error: $e'};
    }
  }

  void _checkSuccess(Map<String, dynamic> response) {
    if (response['success'] != true) {
      throw AuthonException(response['message'] ?? 'Unknown error');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════════════

  /// Initializes the connection to the Authon API.
  /// Must be called before any other API method.
  ///
  /// Returns [AppInfo] on success.
  /// Throws [AuthonException] on failure.
  Future<AppInfo> init() async {
    final response = await _request({'type': 'init'});
    _checkSuccess(response);

    final data = response['data'] as Map<String, dynamic>? ?? {};
    final info = AppInfo.fromJson(data);

    appName = info.name;
    appVersion = info.version;
    hwidLock = info.hwidLock;
    hashCheck = info.hashCheck;
    initialized = true;

    return info;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTHENTICATION
  // ═══════════════════════════════════════════════════════════════════════════

  /// Authenticates with username and password.
  ///
  /// [username] - User's username.
  /// [password] - User's password.
  /// [hwid] - Hardware ID (null to auto-generate).
  ///
  /// Returns [SessionData] on success.
  /// Throws [AuthonException] on failure.
  ///
  /// Possible errors: "Invalid credentials", "Account banned",
  /// "Hardware ID mismatch", "Subscription expired"
  Future<SessionData> login(String username, String password, {String? hwid}) async {
    if (username.isEmpty || password.isEmpty) {
      throw const AuthonException('Username and password are required');
    }

    final response = await _request({
      'type': 'login',
      'username': username,
      'password': password,
      'hwid': hwid ?? await getHWID(),
    });
    _checkSuccess(response);

    final data = response['data'] as Map<String, dynamic>? ?? {};
    final session = SessionData.fromJson(data);
    _extractSession(data);
    return session;
  }

  /// Authenticates using a license key only.
  ///
  /// [licenseKey] - The license key.
  /// [hwid] - Hardware ID (null to auto-generate).
  Future<SessionData> license(String licenseKey, {String? hwid}) async {
    if (licenseKey.isEmpty) {
      throw const AuthonException('License key is required');
    }

    final response = await _request({
      'type': 'license',
      'licenseKey': licenseKey,
      'hwid': hwid ?? await getHWID(),
    });
    _checkSuccess(response);

    final data = response['data'] as Map<String, dynamic>? ?? {};
    final session = SessionData.fromJson(data);
    _extractSession(data);
    return session;
  }

  /// Registers a new user account with a license key.
  ///
  /// Throws [AuthonException] on failure (e.g., "Username already exists").
  Future<void> register(String username, String password, String licenseKey, {String? hwid}) async {
    if (username.isEmpty || password.isEmpty || licenseKey.isEmpty) {
      throw const AuthonException('Username, password, and licenseKey are required');
    }

    final response = await _request({
      'type': 'register',
      'username': username,
      'password': password,
      'licenseKey': licenseKey,
      'hwid': hwid ?? await getHWID(),
    });
    _checkSuccess(response);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SESSION MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /// Validates the current session (heartbeat).
  ///
  /// Returns true if session is valid.
  Future<bool> check() async {
    if (!isAuthenticated) return false;
    final response = await _request({'type': 'check', 'sessionToken': sessionToken});
    return response['success'] == true;
  }

  /// Ends the current session and clears local state.
  Future<bool> logout() async {
    if (!isAuthenticated) return false;
    final response = await _request({'type': 'logout', 'sessionToken': sessionToken});
    if (response['success'] == true) {
      sessionToken = null;
      username = null;
      level = 0;
      subscription = null;
      expiresAt = null;
    }
    return response['success'] == true;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // VARIABLES
  // ═══════════════════════════════════════════════════════════════════════════

  /// Gets an application-level variable (shared across all users).
  Future<String?> getVar(String key) async {
    final response = await _request({
      'type': 'var',
      'key': key,
      'sessionToken': sessionToken ?? '',
    });
    if (response['success'] == true) {
      return (response['data'] as Map<String, dynamic>?)?['value']?.toString();
    }
    return null;
  }

  /// Sets a user-level variable.
  Future<bool> setVar(String key, String value) async {
    final response = await _request({
      'type': 'setvar',
      'key': key,
      'value': value,
      'sessionToken': sessionToken ?? '',
    });
    return response['success'] == true;
  }

  /// Gets a user-level variable.
  Future<String?> getUserVar(String key) async {
    final response = await _request({
      'type': 'getvar',
      'key': key,
      'sessionToken': sessionToken ?? '',
    });
    if (response['success'] == true) {
      return (response['data'] as Map<String, dynamic>?)?['value']?.toString();
    }
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FILES
  // ═══════════════════════════════════════════════════════════════════════════

  /// Lists all files available to the authenticated user.
  Future<List<FileInfo>> listFiles() async {
    if (!isAuthenticated) throw const AuthonException('No active session');

    final response = await _request({
      'type': 'list_files',
      'sessionToken': sessionToken,
    });
    _checkSuccess(response);

    final data = response['data'];
    if (data is List) {
      return data.map((item) => FileInfo.fromJson(item as Map<String, dynamic>)).toList();
    }
    return [];
  }

  /// Downloads a file by its ID.
  ///
  /// Returns raw file bytes.
  Future<List<int>> downloadFile(String fileId) async {
    if (!isAuthenticated || fileId.isEmpty) {
      throw const AuthonException('Session and file ID are required');
    }

    final response = await _request({
      'type': 'file',
      'fileId': fileId,
      'sessionToken': sessionToken,
    });

    if (response.containsKey('binary')) {
      return response['binary'] as List<int>;
    }

    throw const AuthonException('File download failed');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LOGGING & ANALYTICS
  // ═══════════════════════════════════════════════════════════════════════════

  /// Sends an activity log to the dashboard.
  Future<bool> log(String message) async {
    final msg = message.length > 500 ? message.substring(0, 500) : message;
    final response = await _request({
      'type': 'log',
      'message': msg,
      'sessionToken': sessionToken ?? '',
    });
    return response['success'] == true;
  }

  /// Gets the list of currently online users.
  Future<OnlineData> fetchOnline() async {
    if (!isAuthenticated) throw const AuthonException('No active session');
    final response = await _request({
      'type': 'fetch_online',
      'sessionToken': sessionToken,
    });
    _checkSuccess(response);
    return OnlineData.fromJson(response['data'] as Map<String, dynamic>? ?? {});
  }

  /// Gets application statistics.
  Future<StatsData> fetchStats() async {
    if (!isAuthenticated) throw const AuthonException('No active session');
    final response = await _request({
      'type': 'fetch_stats',
      'sessionToken': sessionToken,
    });
    _checkSuccess(response);
    return StatsData.fromJson(response['data'] as Map<String, dynamic>? ?? {});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY
  // ═══════════════════════════════════════════════════════════════════════════

  /// Checks if an IP or HWID is blacklisted.
  Future<BlacklistData> checkBlacklist({String? ip, String? hwid}) async {
    final payload = <String, dynamic>{'type': 'check_blacklist'};
    if (ip != null && ip.isNotEmpty) payload['ip'] = ip;
    if (hwid != null && hwid.isNotEmpty) payload['hwid'] = hwid;

    final response = await _request(payload);
    _checkSuccess(response);
    return BlacklistData.fromJson(response['data'] as Map<String, dynamic>? ?? {});
  }

  /// Redeems a referral code for bonus subscription days.
  Future<ReferralData> redeemReferral(String code) async {
    if (!isAuthenticated || code.isEmpty) {
      throw const AuthonException('Session and referral code are required');
    }

    final response = await _request({
      'type': 'redeem_referral',
      'code': code,
      'sessionToken': sessionToken,
    });
    _checkSuccess(response);

    final data = response['data'] as Map<String, dynamic>? ?? {};
    return ReferralData(
      expiresAt: data['expiresAt'] ?? '',
      rewardDays: data['rewardDays'] ?? 0,
      message: response['message'] ?? '',
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  void _extractSession(Map<String, dynamic> data) {
    sessionToken = data['sessionToken'] as String?;
    username = data['username'] as String?;
    level = data['level'] as int? ?? 0;
    subscription = data['subscription'] as String?;
    expiresAt = data['expiresAt'] as String?;
  }
}

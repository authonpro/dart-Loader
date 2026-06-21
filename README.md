# Authon Dart/Flutter SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Dart/Flutter SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/MTY79JDFm6">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Dart 3.0+ / Flutter 3.10+
- `http` package

## Installation

```yaml
dependencies:
  authon:
    git:
      url: https://github.com/authonpro/sdk-dart
```

Or copy `authon.dart` into your project.

## Quick Start

```dart
import 'package:authon/authon.dart';

final auth = Authon('your-app-id', 'your-api-key');
await auth.init();

final result = await auth.login('username', 'password');
if (result['success']) {
  print('Level: ${auth.level}');
}
await auth.logout();
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/MTY79JDFm6
- 📊 Status: https://authon.pro/status
- 🔗 API Health: https://api.authon.pro/health

## License

MIT

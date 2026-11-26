// Pulse VPN - Application Entry Point & Cyber-Minimalist Dark Theme
// lib/main.dart

import 'package:flutter/material.dart';
import 'ui/home_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const PulseVpnApp());
}

class PulseVpnApp extends StatelessWidget {
  const PulseVpnApp({super.key});

  static const Color obsidianBg = Color(0xFF07090E);
  static const Color surfaceCard = Color(0xFF111622);
  static const Color cyberCyan = Color(0xFF00F0FF);
  static const Color emeraldPulse = Color(0xFF10B981);
  static const Color slateBorder = Color(0xFF1E293B);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Pulse VPN',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: obsidianBg,
        primaryColor: cyberCyan,
        colorScheme: const ColorScheme.dark(
          primary: cyberCyan,
          secondary: emeraldPulse,
          surface: surfaceCard,
        ),
        cardColor: surfaceCard,
        dividerColor: slateBorder,
        useMaterial3: true,
      ),
      home: const PulseDashboardScreen(),
    );
  }
}

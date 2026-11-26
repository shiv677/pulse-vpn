// Pulse VPN - Cyber-Minimalist Pro Authentication Modal (Login & Sign-Up)
// lib/ui/widgets/auth_modal.dart

import 'package:flutter/material.dart';
import '../../core/auth_service.dart';

class AuthModal extends StatefulWidget {
  final AuthService authService;
  final ValueChanged<UserSession?> onSessionUpdated;

  const AuthModal({
    super.key,
    required this.authService,
    required this.onSessionUpdated,
  });

  @override
  State<AuthModal> createState() => _AuthModalState();
}

class _AuthModalState extends State<AuthModal> {
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();

  bool _isSignUpMode = false;
  bool _requestProTier = true;
  bool _isLoading = false;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    final session = widget.authService.currentSession;
    if (session != null) {
      _emailController.text = session.email;
    } else {
      _emailController.text = 'shivansh.pro@pulsevpn.io';
    }
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submitAuth() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final email = _emailController.text.trim();
      final password = _passwordController.text;
      final selectedTier = _requestProTier ? UserTier.pro : UserTier.free;

      final UserSession session;
      if (_isSignUpMode) {
        session = await widget.authService.signUp(
          email: email,
          password: password,
          tier: selectedTier,
        );
      } else {
        session = await widget.authService.logIn(
          email: email,
          password: password,
          overrideTier: selectedTier,
        );
      }

      widget.onSessionUpdated(session);
      if (mounted) {
        Navigator.of(context).pop(session);
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _errorMessage = e.toString().replaceFirst('Invalid argument(s): ', '');
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
      }
    }
  }

  Future<void> _handleLogOut() async {
    await widget.authService.logOut();
    widget.onSessionUpdated(null);
    if (mounted) {
      Navigator.of(context).pop(null);
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentSession = widget.authService.currentSession;
    final isProActive = currentSession?.isPro ?? _requestProTier;
    final accentColor = isProActive ? const Color(0xFF10B981) : const Color(0xFF00F0FF);

    return Dialog(
      backgroundColor: const Color(0xFF0D121C),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18),
        side: BorderSide(color: accentColor.withOpacity(0.45)),
      ),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 440),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    _isSignUpMode ? 'CREATE PULSE ACCOUNT' : 'PULSE // ACCOUNT LOGIN',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.5,
                    ),
                  ),
                  _buildProTierBadge(isProActive, accentColor),
                ],
              ),
              const SizedBox(height: 18),
              if (currentSession != null) ...[
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: const Color(0xFF111622),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: const Color(0xFF1E293B)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'ACTIVE SESSION // ${currentSession.email}',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Tier: ${currentSession.tier.name.toUpperCase()} • ID: ${currentSession.userId}',
                        style: TextStyle(color: accentColor, fontSize: 11),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
              ],
              TextField(
                key: const Key('auth_email_field'),
                controller: _emailController,
                style: const TextStyle(color: Colors.white, fontSize: 13),
                decoration: InputDecoration(
                  labelText: 'Email Address',
                  labelStyle: const TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                  prefixIcon: const Icon(Icons.alternate_email, color: Color(0xFF64748B), size: 18),
                  filled: true,
                  fillColor: const Color(0xFF111622),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: Color(0xFF1E293B)),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('auth_password_field'),
                controller: _passwordController,
                obscureText: true,
                style: const TextStyle(color: Colors.white, fontSize: 13),
                decoration: InputDecoration(
                  labelText: 'Password or Supabase JWT',
                  labelStyle: const TextStyle(color: Color(0xFF94A3B8), fontSize: 12),
                  prefixIcon: const Icon(Icons.lock_outline, color: Color(0xFF64748B), size: 18),
                  filled: true,
                  fillColor: const Color(0xFF111622),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10),
                    borderSide: const BorderSide(color: Color(0xFF1E293B)),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text(
                  'Enable Pulse Pro Tier (5s Fast-Hop Multi-Relay)',
                  style: TextStyle(color: Color(0xFFCBD5E1), fontSize: 12),
                ),
                value: _requestProTier,
                activeColor: const Color(0xFF10B981),
                onChanged: (val) => setState(() => _requestProTier = val),
              ),
              if (_errorMessage != null) ...[
                const SizedBox(height: 8),
                Container(
                  key: const Key('auth_error_banner'),
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: const Color(0xFFEF4444).withOpacity(0.14),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: const Color(0xFFEF4444)),
                  ),
                  child: Text(
                    _errorMessage!,
                    style: const TextStyle(
                      color: Color(0xFFFCA5A5),
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              ElevatedButton(
                key: const Key('auth_submit_button'),
                onPressed: _isLoading ? null : _submitAuth,
                style: ElevatedButton.styleFrom(
                  backgroundColor: accentColor,
                  foregroundColor: const Color(0xFF07090E),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
                child: _isLoading
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Color(0xFF07090E),
                        ),
                      )
                    : Text(
                        _isSignUpMode ? 'SIGN UP & ACTIVATE' : 'AUTHENTICATE SESSION',
                        style: const TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1.2,
                        ),
                      ),
              ),
              const SizedBox(height: 10),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  TextButton(
                    onPressed: () => setState(() => _isSignUpMode = !_isSignUpMode),
                    child: Text(
                      _isSignUpMode ? 'Already registered? Login' : 'Need an account? Sign-up',
                      style: const TextStyle(color: Color(0xFF94A3B8), fontSize: 11),
                    ),
                  ),
                  if (currentSession != null)
                    TextButton(
                      onPressed: _handleLogOut,
                      child: const Text(
                        'Log Out',
                        style: TextStyle(color: Color(0xFFF87171), fontSize: 11),
                      ),
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildProTierBadge(bool isPro, Color accentColor) {
    return Container(
      key: const Key('pro_tier_badge'),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: accentColor.withOpacity(0.15),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: accentColor),
      ),
      child: Text(
        isPro ? 'PRO TIER' : 'FREE TIER',
        style: TextStyle(
          color: accentColor,
          fontSize: 10,
          fontWeight: FontWeight.w800,
          letterSpacing: 1.1,
        ),
      ),
    );
  }
}

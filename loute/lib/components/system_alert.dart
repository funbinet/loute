import 'dart:async';
import 'package:flutter/material.dart';
import '../main.dart';
import '../themes/midnight_hacker.dart';

enum AlertType { positive, negative, ignorable }

enum AlertContext {
  save,
  delete,
  download,
  offline,
  online,
  error,
  warning,
  info,
  run,
  inputInvalid,
  backendError,
  frontendError,
  systemFailure,
  networkTimeout,
  success,
  config,
  refresh,
  auth,
  security,
  upload,
}

extension AlertContextIcon on AlertContext {
  IconData get icon {
    switch (this) {
      case AlertContext.save: return Icons.save_outlined;
      case AlertContext.delete: return Icons.delete_outline;
      case AlertContext.download: return Icons.download_outlined;
      case AlertContext.offline: return Icons.wifi_off_outlined;
      case AlertContext.online: return Icons.wifi_outlined;
      case AlertContext.error: return Icons.cancel_outlined;
      case AlertContext.warning: return Icons.warning_amber_outlined;
      case AlertContext.info: return Icons.info_outline;
      case AlertContext.run: return Icons.play_circle_outline;
      case AlertContext.inputInvalid: return Icons.rule_outlined;
      case AlertContext.backendError: return Icons.dns_outlined;
      case AlertContext.frontendError: return Icons.web_asset_off_outlined;
      case AlertContext.systemFailure: return Icons.dangerous_outlined;
      case AlertContext.networkTimeout: return Icons.timer_off_outlined;
      case AlertContext.success: return Icons.check_circle_outline;
      case AlertContext.config: return Icons.settings_outlined;
      case AlertContext.refresh: return Icons.refresh_outlined;
      case AlertContext.auth: return Icons.lock_outline;
      case AlertContext.security: return Icons.security_outlined;
      case AlertContext.upload: return Icons.upload_file_outlined;
    }
  }
}

class _AlertData {
  final String id;
  final String title;
  final String message;
  final AlertType type;
  final AlertContext alertContext;

  _AlertData({
    required this.id,
    required this.title,
    required this.message,
    required this.type,
    required this.alertContext,
  });
}

class SystemAlert {
  static final GlobalKey<AnimatedListState> _listKey = GlobalKey<AnimatedListState>();
  static final List<_AlertData> _items = [];
  static OverlayEntry? _overlayEntry;

  static void show({
    required String title,
    required String message,
    required AlertType type,
    required AlertContext context,
  }) {
    final overlayState = navigatorKey.currentState?.overlay;
    if (overlayState == null) return;

    if (_overlayEntry == null) {
      _overlayEntry = OverlayEntry(builder: (ctx) => const _AlertOverlayManager());
      overlayState.insert(_overlayEntry!);
    }

    final id = DateTime.now().microsecondsSinceEpoch.toString();
    final alert = _AlertData(
      id: id,
      title: title,
      message: message,
      type: type,
      alertContext: context,
    );

    _items.add(alert);
    _listKey.currentState?.insertItem(_items.length - 1);

    // Determine duration
    bool isPersistent = false;
    Duration duration = const Duration(seconds: 4);

    if (type == AlertType.negative) {
      if (context == AlertContext.systemFailure || context == AlertContext.security || context == AlertContext.backendError) {
        isPersistent = true; // Very dangerous: stays forever until dismissed manually
      } else {
        duration = const Duration(seconds: 10); // Dangerous: stays longer
      }
    } else if (type == AlertType.ignorable) {
      duration = const Duration(seconds: 6);
    }

    if (!isPersistent) {
      Timer(duration, () {
        _removeAlert(id);
      });
    }
  }

  static void _removeAlert(String id) {
    final index = _items.indexWhere((a) => a.id == id);
    if (index != -1) {
      final removed = _items.removeAt(index);
      _listKey.currentState?.removeItem(
        index,
        (context, animation) => _buildItem(removed, animation),
        duration: const Duration(milliseconds: 300),
      );
    }
  }

  static Widget _buildItem(_AlertData alert, Animation<double> animation) {
    return _AnimatedAlertItem(
      alert: alert,
      animation: animation,
      onDismiss: () => _removeAlert(alert.id),
    );
  }
}

class _AlertOverlayManager extends StatelessWidget {
  const _AlertOverlayManager();

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    double maxWidth = width * 0.35;
    if (maxWidth > 450) maxWidth = 450;
    if (maxWidth < 300) maxWidth = 300;

    return Positioned(
      top: 80, // A bit below the header
      right: 0,
      width: maxWidth,
      child: IgnorePointer(
        ignoring: false,
        child: AnimatedList(
          key: SystemAlert._listKey,
          shrinkWrap: true,
          initialItemCount: SystemAlert._items.length,
          itemBuilder: (context, index, animation) {
            return SystemAlert._buildItem(SystemAlert._items[index], animation);
          },
        ),
      ),
    );
  }
}

class _AnimatedAlertItem extends StatelessWidget {
  final _AlertData alert;
  final Animation<double> animation;
  final VoidCallback onDismiss;

  const _AnimatedAlertItem({
    required this.alert,
    required this.animation,
    required this.onDismiss,
  });

  Color get _color {
    switch (alert.type) {
      case AlertType.positive: return MidnightHacker.primary; // Green
      case AlertType.negative: return MidnightHacker.negative; // Red
      case AlertType.ignorable: return MidnightHacker.positive; // Amber
    }
  }

  @override
  Widget build(BuildContext context) {
    final offsetAnimation = Tween<Offset>(begin: const Offset(1.0, 0.0), end: Offset.zero)
        .animate(CurvedAnimation(parent: animation, curve: Curves.easeOutQuart));

    return SlideTransition(
      position: offsetAnimation,
      child: FadeTransition(
        opacity: animation,
        child: Material(
          type: MaterialType.transparency,
          child: Padding(
            padding: const EdgeInsets.only(bottom: 12.0),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              const SizedBox(width: 16), // Margin on the left
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                  decoration: BoxDecoration(
                    color: MidnightHacker.background, // Pure black background
                    border: Border.all(color: _color, width: 1.5),
                  ),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(alert.alertContext.icon, color: _color, size: 24),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              alert.title.toUpperCase(),
                              style: MidnightHacker.monoStyle.copyWith(
                                color: _color,
                                fontWeight: FontWeight.bold,
                                fontSize: 14,
                                letterSpacing: 1,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Text(
                              alert.message,
                              style: MidnightHacker.monoSmall.copyWith(color: _color, height: 1.4),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 12),
                      MouseRegion(
                        cursor: SystemMouseCursors.click,
                        child: GestureDetector(
                          onTap: onDismiss,
                          child: Icon(Icons.close, color: _color, size: 18),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              // Connecting line to the right edge
              Container(
                width: 24, // 1 cm approx depending on DPI
                height: 1.5,
                color: _color,
              ),
            ],
          ),
        ),
        ),
      ),
    );
  }
}

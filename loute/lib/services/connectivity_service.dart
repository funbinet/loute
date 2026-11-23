import 'dart:async';
import 'package:http/http.dart' as http;
import '../components/system_alert.dart';

class ConnectivityService {
  static final ConnectivityService _instance = ConnectivityService._internal();
  factory ConnectivityService() => _instance;
  ConnectivityService._internal();

  bool _isOnline = true; // Assume online initially to avoid startup spam
  Timer? _timer;

  void startMonitoring() {
    _timer = Timer.periodic(const Duration(seconds: 10), (timer) async {
      final online = await _checkConnection();
      if (online != _isOnline) {
        _isOnline = online;
        if (_isOnline) {
          SystemAlert.show(
            title: 'CONNECTION RESTORED',
            message: 'System is back online. Network operations can resume.',
            type: AlertType.positive,
            context: AlertContext.online,
          );
        } else {
          SystemAlert.show(
            title: 'CONNECTION LOST',
            message: 'System is offline. Network operations will fail.',
            type: AlertType.negative,
            context: AlertContext.offline,
          );
        }
      }
    });
  }

  void stopMonitoring() {
    _timer?.cancel();
  }

  Future<bool> _checkConnection() async {
    try {
      final response = await http.get(Uri.parse('https://8.8.8.8')).timeout(const Duration(seconds: 3));
      return response.statusCode > 0; // Any response means we can route traffic
    } catch (_) {
      try {
        final response = await http.get(Uri.parse('https://1.1.1.1')).timeout(const Duration(seconds: 3));
        return response.statusCode > 0;
      } catch (_) {
        return false;
      }
    }
  }
}

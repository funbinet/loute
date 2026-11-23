import 'package:flutter_riverpod/flutter_riverpod.dart';

class SettingsState {
  final int defaultConcurrency;
  final int defaultTimeout;
  final String exportFormat; // json, csv, txt
  final String? webhookUrl;
  final String systemVersion;

  const SettingsState({
    this.defaultConcurrency = 100,
    this.defaultTimeout = 10,
    this.exportFormat = 'json',
    this.webhookUrl,
    this.systemVersion = '1.0.0+1',
  });

  SettingsState copyWith({
    int? defaultConcurrency,
    int? defaultTimeout,
    String? exportFormat,
    String? webhookUrl,
    String? systemVersion,
  }) {
    return SettingsState(
      defaultConcurrency: defaultConcurrency ?? this.defaultConcurrency,
      defaultTimeout: defaultTimeout ?? this.defaultTimeout,
      exportFormat: exportFormat ?? this.exportFormat,
      webhookUrl: webhookUrl ?? this.webhookUrl,
      systemVersion: systemVersion ?? this.systemVersion,
    );
  }
}

class SettingsNotifier extends StateNotifier<SettingsState> {
  SettingsNotifier() : super(const SettingsState());

  void setConcurrency(int v) => state = state.copyWith(defaultConcurrency: v);
  void setTimeout(int v) => state = state.copyWith(defaultTimeout: v);
  void setExportFormat(String v) => state = state.copyWith(exportFormat: v);
  void setWebhookUrl(String v) => state = state.copyWith(webhookUrl: v);
}

final settingsProvider =
    StateNotifierProvider<SettingsNotifier, SettingsState>(
  (ref) => SettingsNotifier(),
);

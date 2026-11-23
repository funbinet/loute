import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/report_model.dart';

enum ActionStatus {
  idle,
  running,
  stopped,
  completed,
}

class ActionSession {
  final String actionId;
  final ActionStatus status;
  final double progress;
  final List<String> logs;
  final String? output;
  final Map<String, String> inputs;
  final ReportRecord? report;
  final ReportPayload? reportPayload;
  final String? jsonOutput;
  final String? txtOutput;
  final String? csvOutput;
  final String? cveOutput;

  ActionSession({
    required this.actionId,
    this.status = ActionStatus.idle,
    this.progress = 0.0,
    this.logs = const [],
    this.output,
    this.inputs = const {},
    this.report,
    this.reportPayload,
    this.jsonOutput,
    this.txtOutput,
    this.csvOutput,
    this.cveOutput,
  });

  ActionSession copyWith({
    ActionStatus? status,
    double? progress,
    List<String>? logs,
    String? output,
    Map<String, String>? inputs,
    ReportRecord? report,
    ReportPayload? reportPayload,
    String? jsonOutput,
    String? txtOutput,
    String? csvOutput,
    String? cveOutput,
  }) {
    return ActionSession(
      actionId: actionId,
      status: status ?? this.status,
      progress: progress ?? this.progress,
      logs: logs ?? this.logs,
      output: output ?? this.output,
      inputs: inputs ?? this.inputs,
      report: report ?? this.report,
      reportPayload: reportPayload ?? this.reportPayload,
      jsonOutput: jsonOutput ?? this.jsonOutput,
      txtOutput: txtOutput ?? this.txtOutput,
      csvOutput: csvOutput ?? this.csvOutput,
      cveOutput: cveOutput ?? this.cveOutput,
    );
  }
}

class ActionSessionNotifier extends StateNotifier<Map<String, ActionSession>> {
  ActionSessionNotifier() : super({});

  ActionSession getSession(String actionId) {
    return state[actionId] ?? ActionSession(actionId: actionId);
  }

  void updateInput(String actionId, String key, String value) {
    final session = getSession(actionId);
    final updatedInputs = Map<String, String>.from(session.inputs);
    updatedInputs[key] = value;
    state = {...state, actionId: session.copyWith(inputs: updatedInputs)};
  }

  void startAction(String actionId, String startLog) {
    final session = getSession(actionId);
    state = {
      ...state,
      actionId: session.copyWith(
        status: ActionStatus.running,
        progress: 0.2,
        logs: [startLog],
        output: null,
        report: null,
        reportPayload: null,
        jsonOutput: null,
        txtOutput: null,
        csvOutput: null,
        cveOutput: null,
      ),
    };
  }

  void addLog(String actionId, String log, {double? progress}) {
    final session = getSession(actionId);
    if (session.status == ActionStatus.stopped) return;
    state = {
      ...state,
      actionId: session.copyWith(
        logs: [...session.logs, log],
        progress: progress ?? session.progress,
      ),
    };
  }

  void finishAction(
    String actionId,
    String output,
    String endLog, {
    ReportRecord? report,
    ReportPayload? reportPayload,
    String? jsonOutput,
    String? txtOutput,
    String? csvOutput,
    String? cveOutput,
  }) {
    final session = getSession(actionId);
    if (session.status == ActionStatus.stopped) return;
    state = {
      ...state,
      actionId: session.copyWith(
        status: ActionStatus.completed,
        progress: 1.0,
        logs: [...session.logs, endLog],
        output: output,
        report: report,
        reportPayload: reportPayload,
        jsonOutput: jsonOutput,
        txtOutput: txtOutput,
        csvOutput: csvOutput,
        cveOutput: cveOutput,
      ),
    };
  }

  void failAction(
    String actionId,
    String errorLog,
    String errorOutput, {
    ReportRecord? report,
    ReportPayload? reportPayload,
  }) {
    final session = getSession(actionId);
    if (session.status == ActionStatus.stopped) return;
    state = {
      ...state,
      actionId: session.copyWith(
        status: ActionStatus.completed,
        progress: 1.0,
        logs: [...session.logs, errorLog],
        output: errorOutput,
        report: report ?? session.report,
        reportPayload: reportPayload ?? session.reportPayload,
      ),
    };
  }

  void stopAction(String actionId) {
    final session = getSession(actionId);
    final now = DateTime.now();
    final ts = '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}:${now.second.toString().padLeft(2, '0')}';
    state = {
      ...state,
      actionId: session.copyWith(
        status: ActionStatus.stopped,
        progress: 0.0,
        logs: [...session.logs, '[$ts] USER CANCELLED ACTION'],
      ),
    };
  }

  void updateReportFormats(
    String actionId, {
    ReportRecord? report,
    String? jsonOutput,
    String? txtOutput,
    String? csvOutput,
    String? cveOutput,
  }) {
    final session = getSession(actionId);
    state = {
      ...state,
      actionId: session.copyWith(
        report: report ?? session.report,
        jsonOutput: jsonOutput ?? session.jsonOutput,
        txtOutput: txtOutput ?? session.txtOutput,
        csvOutput: csvOutput ?? session.csvOutput,
        cveOutput: cveOutput ?? session.cveOutput,
      ),
    };
  }
}

final actionSessionProvider =
    StateNotifierProvider<ActionSessionNotifier, Map<String, ActionSession>>(
  (ref) => ActionSessionNotifier(),
);

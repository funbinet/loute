import 'dart:convert';
import '../models/report_model.dart';
import '../utils/format_utils.dart';

class JsonEngine {
  static String render(ReportPayload payload) {
    final Map<String, dynamic> structuredReport = {
      "\$schema": "https://loute.io/schemas/report-v1.json",
      "meta": {
        "report_id": payload.id,
        "framework": "LOUTE Autonomous Bug Bounty Framework",
        "version": payload.systemVersion,
        "generated_at": payload.timestamp.toUtc().toIso8601String(),
      },
      "execution": {
        "action_id": payload.actionId,
        "action_name": payload.actionName,
        "module_name": payload.moduleName,
        "phase_name": payload.phaseName,
        "status": payload.status,
        "inputs": payload.inputs,
      },
      "results": {
        "findings_count": payload.findings.length,
        "findings": payload.findings.map((f) {
          return {
            "title": f['title'] ?? 'Untitled Finding',
            "type": f['type'] ?? 'generic',
            "severity": (f['severity']?.toString() ?? 'info').toLowerCase(),
            "status": f['status'] ?? 'detected',
            "description": f['description'] ?? '',
            "evidence": f['evidence'] ?? '',
            "timestamp": f['timestamp'] ?? payload.timestamp.toUtc().toIso8601String(),
          };
        }).toList(),
      },
      "telemetry": {
        "raw_output": FormatUtils.stripHtmlTags(payload.rawOutput),
        "console_logs": payload.logs,
      }
    };

    return const JsonEncoder.withIndent('  ').convert(structuredReport);
  }
}

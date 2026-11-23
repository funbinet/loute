import '../models/report_model.dart';
import '../utils/format_utils.dart';

class TxtEngine {
  static String render(ReportPayload payload) {
    final buffer = StringBuffer();

    // Premium Centered Cyberpunk Double-Lined Header
    buffer.writeln('╔══════════════════════════════════════════════════════════════════════════════╗');
    buffer.writeln('║                                                                              ║');
    buffer.writeln('║                               ╦  ╔═╗╦  ╦╔═╗╔═╗                               ║');
    buffer.writeln('║                               ║  ║ ║║  ║║  ║╣                                ║');
    buffer.writeln('║                               ╩═╝╚═╝╚══╝╚═╝╚═╝                               ║');
    buffer.writeln('║                                                                              ║');
    buffer.writeln('║                     AUTONOMOUS BUG BOUNTY SYSTEM REPORT                      ║');
    buffer.writeln('╚══════════════════════════════════════════════════════════════════════════════╝');

    buffer.writeln();
    buffer.writeln(' [SYSTEM METADATA]');
    buffer.writeln(' ├─ Report Signature : ${payload.id}');
    buffer.writeln(' ├─ Target Action    : ${payload.actionName} (${payload.actionId})');
    if (payload.moduleName.isNotEmpty) {
      buffer.writeln(' ├─ Module Identifier: ${payload.moduleName}');
    }
    if (payload.phaseName.isNotEmpty) {
      buffer.writeln(' ├─ Framework Phase  : ${payload.phaseName}');
    }
    buffer.writeln(' ├─ Execution Status : ${payload.status.toUpperCase()}');
    buffer.writeln(' ├─ System Version   : ${payload.systemVersion}');
    buffer.writeln(' └─ Scan Timestamp   : ${payload.timestamp.toUtc().toIso8601String()} UTC');

    buffer.writeln();
    buffer.writeln(' [INPUT CONFIGURATION]');
    if (payload.inputs.isEmpty) {
      buffer.writeln('   (none)');
    } else {
      final entries = payload.inputs.entries.toList();
      for (var i = 0; i < entries.length; i++) {
        final isLast = i == entries.length - 1;
        final branch = isLast ? '   └─ ' : '   ├─ ';
        final paddedKey = entries[i].key.padRight(18);
        buffer.writeln('$branch$paddedKey: ${entries[i].value}');
      }
    }

    buffer.writeln();
    buffer.writeln(' [VULNERABILITY & FINDINGS ANALYSIS]');
    if (payload.findings.isEmpty) {
      buffer.writeln('   ┌────────────────────────────────────────────────────────────────────────┐');
      buffer.writeln('   │ NO VULNERABILITIES OR INTERESTING FINDINGS DETECTED ON TARGET HOST     │');
      buffer.writeln('   └────────────────────────────────────────────────────────────────────────┘');
    } else {
      for (var i = 0; i < payload.findings.length; i++) {
        final f = payload.findings[i];
        final num = i + 1;
        final severity = (f['severity']?.toString() ?? 'INFO').toUpperCase();
        
        buffer.writeln('   ┌─ [FINDING #$num] ────────────────────────────────────────────────────────');
        buffer.writeln('   │  Title       : ${f['title']}');
        buffer.writeln('   │  Type        : ${f['type']}');
        buffer.writeln('   │  Severity    : $severity');
        buffer.writeln('   │  Status      : ${f['status']?.toString().toUpperCase()}');
        buffer.writeln('   │  Description :');
        
        final desc = f['description']?.toString() ?? '';
        final wrappedDesc = _wrapText(desc, 66);
        for (final line in wrappedDesc) {
          buffer.writeln('   │    $line');
        }
        
        if (f['evidence'] != null) {
          buffer.writeln('   │  Evidence    :');
          final wrappedEvidence = _wrapText(f['evidence'].toString(), 66);
          for (final line in wrappedEvidence) {
            buffer.writeln('   │    $line');
          }
        }
        
        buffer.writeln('   └────────────────────────────────────────────────────────────────────────');
        buffer.writeln();
      }
    }

    buffer.writeln(' [RAW COMMAND OUTPUT]');
    buffer.writeln(' ──────────────────────────────────────────────────────────────────────────────');
    final strippedOutput = FormatUtils.stripHtmlTags(payload.rawOutput).trim();
    if (strippedOutput.isEmpty) {
      buffer.writeln(' (Command executed with empty stdout/stderr)');
    } else {
      buffer.writeln(strippedOutput);
    }
    buffer.writeln(' ──────────────────────────────────────────────────────────────────────────────');

    buffer.writeln();
    buffer.writeln(' [CONSOLE LOG STREAM]');
    if (payload.logs.isEmpty) {
      buffer.writeln('   (no console logs recorded)');
    } else {
      for (final line in payload.logs) {
        buffer.writeln('   [LOG] $line');
      }
    }
    
    buffer.writeln();
    buffer.writeln('================================================================================');
    buffer.writeln('                END OF LOUTE AUTONOMOUS RECONNAISSANCE REPORT                  ');
    buffer.writeln('================================================================================');

    return buffer.toString();
  }

  static List<String> _wrapText(String text, int width) {
    if (text.isEmpty) return [];
    final List<String> lines = [];
    final List<String> words = text.split(' ');
    var currentLine = '';

    for (final word in words) {
      if (currentLine.isEmpty) {
        currentLine = word;
      } else if (currentLine.length + word.length + 1 <= width) {
        currentLine += ' $word';
      } else {
        lines.add(currentLine);
        currentLine = word;
      }
    }
    if (currentLine.isNotEmpty) {
      lines.add(currentLine);
    }
    return lines;
  }
}

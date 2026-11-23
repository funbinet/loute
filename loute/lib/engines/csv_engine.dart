import '../models/report_model.dart';

class CsvEngine {
  static String render(ReportPayload payload) {
    if (payload.findings.isEmpty) {
      // Return standard headers even if empty
      final standardHeaders = [
        'finding_num',
        'title',
        'severity',
        'type',
        'status',
        'description',
        'evidence',
        'timestamp'
      ];
      return '${standardHeaders.map(_escapeCsv).join(',')}\n';
    }

    // 1. Define standard, highly structured primary columns
    final primaryHeaders = [
      'finding_num',
      'title',
      'severity',
      'type',
      'status',
      'description',
      'evidence',
      'timestamp'
    ];

    // 2. Discover any additional custom/dynamic keys from the findings
    final customHeaders = <String>{};
    for (final finding in payload.findings) {
      for (final key in finding.keys) {
        final lowerKey = key.toString().toLowerCase();
        if (!primaryHeaders.contains(lowerKey)) {
          customHeaders.add(key.toString());
        }
      }
    }

    final headerList = [...primaryHeaders, ...customHeaders];

    final buffer = StringBuffer();
    // Write headers
    buffer.writeln(headerList.map(_escapeCsv).join(','));

    // Write rows
    for (var i = 0; i < payload.findings.length; i++) {
      final finding = payload.findings[i];
      final rowValues = headerList.map((header) {
        if (header == 'finding_num') {
          return (i + 1).toString();
        }
        // Check finding values with case-insensitive fallback for standard keys
        dynamic val = finding[header];
        if (val == null) {
          // Check case variation (e.g. Title vs title)
          for (final key in finding.keys) {
            if (key.toString().toLowerCase() == header.toLowerCase()) {
              val = finding[key];
              break;
            }
          }
        }
        return val?.toString() ?? '';
      });
      
      buffer.writeln(rowValues.map(_escapeCsv).join(','));
    }

    return buffer.toString();
  }

  static String _escapeCsv(String value) {
    // RFC-4180 standard escaping for carriage returns, newlines, commas, and double quotes
    final needsQuotes = value.contains(',') || 
                        value.contains('"') || 
                        value.contains('\n') || 
                        value.contains('\r');
    final escaped = value.replaceAll('"', '""');
    return needsQuotes ? '"$escaped"' : escaped;
  }
}

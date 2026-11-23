import 'dart:convert';
import 'package:flutter/services.dart' show rootBundle;
import '../models/report_model.dart';
import '../engines/html_engine.dart';
import '../engines/json_engine.dart';
import '../engines/csv_engine.dart';
import '../engines/txt_engine.dart';
import '../engines/cve_engine.dart';

class ReportRenderer {
  static String? _logoBase64;

  static Future<String> _loadLogoBase64() async {
    if (_logoBase64 != null) {
      return _logoBase64!;
    }
    final data = await rootBundle.load('assets/icons/logo.png');
    _logoBase64 = base64Encode(data.buffer.asUint8List());
    return _logoBase64!;
  }

  static Future<String> renderHtml(ReportPayload payload) async {
    final logoBase64 = await _loadLogoBase64();
    // Use ONLY HtmlEngine for HTML rendering - consistent style
    return HtmlEngine.render(payload, logoBase64);
  }

  static String renderJson(ReportPayload payload) {
    // Use JsonEngine for consistent JSON formatting
    return JsonEngine.render(payload);
  }

  static String renderTxt(ReportPayload payload) {
    // Use TxtEngine for consistent text formatting
    return TxtEngine.render(payload);
  }

  static String renderCsv(ReportPayload payload) {
    // Use CsvEngine for consistent CSV formatting
    return CsvEngine.render(payload);
  }

  static String renderCve(ReportPayload payload) {
    // Use CveEngine for consistent CVE formatting
    return CveEngine.render(payload);
  }

}

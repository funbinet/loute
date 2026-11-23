import 'dart:io';
import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../themes/midnight_hacker.dart';
import '../components/system_alert.dart';

/// Renders a premium, state-of-the-art interactive Summary Dashboard and HTML launch pad.
/// This completely bypasses native WebKitGTK OpenGL initialization to prevent fatal 
/// DRI3 rendering context crashes on Linux/Kali virtual machines, while offering 
/// 100% pixel-perfect layout viewing in the user's default system browser.
class OutputViewer extends StatefulWidget {
  final String htmlContent;
  final String? filePath;

  const OutputViewer({super.key, required this.htmlContent, this.filePath});

  @override
  State<OutputViewer> createState() => _OutputViewerState();
}

class _OutputViewerState extends State<OutputViewer> {
  bool _isLaunching = false;

  // Extract finding counts from the compiled HTML report using regex
  Map<String, int> _parseSeverityCounts() {
    int count(String level) {
      final patterns = [
        RegExp('data-severity="$level"', caseSensitive: false),
        RegExp('sev-badge--$level', caseSensitive: false),
        RegExp('class="[^"]*severity-$level[^"]*"', caseSensitive: false),
      ];
      for (final p in patterns) {
        final m = p.allMatches(widget.htmlContent).length;
        if (m > 0) return m;
      }
      // Fallback: count badge text like >critical< in severity badge spans
      final textPattern = RegExp('>\\s*$level\\s*<', caseSensitive: false);
      return textPattern.allMatches(widget.htmlContent).length;
    }

    return {
      'CRITICAL': count('critical'),
      'HIGH': count('high'),
      'MEDIUM': count('medium'),
      'LOW': count('low'),
      'INFO': count('info'),
    };
  }

  // Parse target action or report title
  String _parseReportTitle() {
    final match = RegExp(r'<title>(.*?)</title>').firstMatch(widget.htmlContent);
    return match?.group(1) ?? 'LOUTE Autonomous Report';
  }

  Future<void> _launchInBrowser() async {
    setState(() {
      _isLaunching = true;
    });

    try {
      File launchFile;
      if (widget.filePath != null && widget.filePath!.isNotEmpty) {
        launchFile = File(widget.filePath!);
        final parentDir = launchFile.parent;
        if (!parentDir.existsSync()) {
          parentDir.createSync(recursive: true);
        }
        if (!launchFile.existsSync()) {
          await launchFile.writeAsString(widget.htmlContent);
        }
      } else {
        // Fallback: save cleanly under outputs/reports/live_view.html (no temp/tmp)
        final reportsDir = Directory('./outputs/reports');
        if (!reportsDir.existsSync()) {
          reportsDir.createSync(recursive: true);
        }
        launchFile = File('./outputs/reports/live_view.html');
        await launchFile.writeAsString(widget.htmlContent);
      }

      final uri = Uri.file(launchFile.absolute.path);
      if (await canLaunchUrl(uri)) {
        await launchUrl(uri, mode: LaunchMode.externalApplication);
      } else {
        // Fallback standard launch
        await launchUrl(uri);
      }
    } catch (e) {
      if (mounted) {
        SystemAlert.show(
          title: 'LAUNCH ERROR',
          message: 'Error opening report: $e',
          type: AlertType.negative,
          context: AlertContext.error,
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isLaunching = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final counts = _parseSeverityCounts();
    final title = _parseReportTitle();
    final totalFindings = counts.values.reduce((a, b) => a + b);

    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: MidnightHacker.panelBg.withOpacity(0.4),
        border: Border.all(color: MidnightHacker.primary.withOpacity(0.5), width: 1.5),
        boxShadow: [
          BoxShadow(
            color: MidnightHacker.primary.withOpacity(0.05),
            blurRadius: 10,
            spreadRadius: 2,
          )
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row with premium icon and report title
            Row(
              children: [
                Icon(Icons.terminal, color: MidnightHacker.primary, size: 24),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    title.toUpperCase(),
                    overflow: TextOverflow.ellipsis,
                    style: MidnightHacker.monoStyle.copyWith(
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                      color: MidnightHacker.primary,
                      letterSpacing: 1.5,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: MidnightHacker.dimGreen.withOpacity(0.1),
                    border: Border.all(color: MidnightHacker.dimGreen.withOpacity(0.3)),
                  ),
                  child: Text(
                    'HTML STANDALONE',
                    style: MidnightHacker.monoSmall.copyWith(
                      color: MidnightHacker.dimGreen,
                      fontSize: 10,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            const Divider(color: MidnightHacker.primary, thickness: 0.5),
            const SizedBox(height: 16),

            // Findings summary layout
            Text(
              'VULNERABILITY METRICS ANALYSIS',
              style: MidnightHacker.monoSmall.copyWith(
                color: Colors.grey,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 12),

            // Symmetrical, premium grid of severity blocks
            LayoutBuilder(
              builder: (context, constraints) {
                final double itemWidth = (constraints.maxWidth - 32) / 5;
                return Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    _buildSeverityBlock('CRITICAL', counts['CRITICAL']!, Colors.red, itemWidth),
                    _buildSeverityBlock('HIGH', counts['HIGH']!, Colors.orange, itemWidth),
                    _buildSeverityBlock('MEDIUM', counts['MEDIUM']!, Colors.yellow, itemWidth),
                    _buildSeverityBlock('LOW', counts['LOW']!, Colors.green, itemWidth),
                    _buildSeverityBlock('INFO', counts['INFO']!, Colors.blue, itemWidth),
                  ],
                );
              },
            ),

            const SizedBox(height: 24),

            // Cyberpunk terminal status log box
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: MidnightHacker.background,
                border: Border.all(color: MidnightHacker.primary.withOpacity(0.2)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.check_circle_outline, color: MidnightHacker.dimGreen, size: 16),
                      const SizedBox(width: 8),
                      Text(
                        'REPORT COMPILED SUCCESSFULLY',
                        style: MidnightHacker.monoSmall.copyWith(
                          color: MidnightHacker.dimGreen,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '├─ Total security findings parsed: $totalFindings\n'
                    '├─ Output location               : ${widget.filePath ?? "outputs/reports/live_view.html"}\n'
                    '└─ Render engine status          : External browser render for pixel-perfect compliance',
                    style: MidnightHacker.monoSmall.copyWith(
                      color: MidnightHacker.dimGreen,
                      height: 1.5,
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 24),

            // Launch button
            SizedBox(
              width: double.infinity,
              height: 48,
              child: ElevatedButton.icon(
                style: ElevatedButton.styleFrom(
                  backgroundColor: MidnightHacker.primary,
                  foregroundColor: MidnightHacker.background,
                  elevation: 4,
                  shadowColor: MidnightHacker.primary.withOpacity(0.3),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.zero,
                    side: BorderSide(color: MidnightHacker.primary, width: 2),
                  ),
                ),
                icon: _isLaunching
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2.5,
                          color: MidnightHacker.background,
                        ),
                      )
                    : const Icon(Icons.open_in_new, size: 20),
                label: Text(
                  _isLaunching ? 'LAUNCHING ENGINE...' : 'LAUNCH IN SYSTEM BROWSER',
                  style: MidnightHacker.monoStyle.copyWith(
                    fontWeight: FontWeight.bold,
                    letterSpacing: 1.5,
                  ),
                ),
                onPressed: _isLaunching ? null : _launchInBrowser,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSeverityBlock(String label, int val, Color color, double width) {
    return Container(
      width: width,
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        border: Border.all(color: color.withOpacity(0.4), width: 1),
      ),
      child: Column(
        children: [
          Text(
            val.toString(),
            style: MidnightHacker.monoStyle.copyWith(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: MidnightHacker.monoSmall.copyWith(
              fontSize: 9,
              fontWeight: FontWeight.bold,
              color: color.withOpacity(0.8),
            ),
          ),
        ],
      ),
    );
  }
}

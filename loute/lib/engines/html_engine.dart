import '../models/report_model.dart';

class HtmlEngine {
  static String render(ReportPayload payload, String logoBase64) {
    final statusClass = _statusClass(payload.status);

    final inputRows = payload.inputs.isEmpty
        ? '<tr><td colspan="2" style="padding: 14px; text-align: center; color: rgba(0, 255, 65, 0.4); font-style: italic;">No input parameters captured.</td></tr>'
        : payload.inputs.entries
            .map((entry) => '<tr>'
                '<td style="padding: 10px 14px; color: rgba(0, 255, 65, 0.5); width: 220px; font-weight: 500; border-bottom: 1px solid rgba(0, 255, 65, 0.1); border-right: 1px solid rgba(0, 255, 65, 0.15);">${_escapeHtml(entry.key)}</td>'
                '<td style="padding: 10px 14px; color: #00ff41; border-bottom: 1px solid rgba(0, 255, 65, 0.1); font-family: \'JetBrains Mono\', monospace;">${_escapeHtml(entry.value)}</td>'
                '</tr>')
            .join();

    final findingsRows = payload.findings.isEmpty
        ? '<tr><td colspan="6" style="padding: 20px; color: rgba(0, 255, 65, 0.4); text-align: center; font-style: italic;">No findings recorded.</td></tr>'
        : payload.findings
            .asMap()
            .entries
            .map((entry) {
              final idx = entry.key + 1;
              final finding = entry.value;
              final type = _safeString(finding['type']);
              final severity = _safeString(finding['severity']).toLowerCase();
              final title = _safeString(finding['title']);
              final description = _safeString(finding['description']);
              final status = _safeString(finding['status']);
              return '<tr>'
                  '<td style="padding: 10px 14px; color: rgba(0, 255, 65, 0.5); border-bottom: 1px solid rgba(0, 255, 65, 0.15);">$idx</td>'
                  '<td style="padding: 10px 14px; color: #00ff41; border-bottom: 1px solid rgba(0, 255, 65, 0.15);">${_escapeHtml(type)}</td>'
                  '<td style="padding: 10px 14px; border-bottom: 1px solid rgba(0, 255, 65, 0.15);">${_renderSeverityBadge(severity)}</td>'
                  '<td style="padding: 10px 14px; color: #00ff41; border-bottom: 1px solid rgba(0, 255, 65, 0.15); font-weight: bold;">${_escapeHtml(title)}</td>'
                  '<td style="padding: 10px 14px; color: rgba(0, 255, 65, 0.6); border-bottom: 1px solid rgba(0, 255, 65, 0.15);">${_escapeHtml(description)}</td>'
                  '<td style="padding: 10px 14px; color: #00ff41; border-bottom: 1px solid rgba(0, 255, 65, 0.15);">${_escapeHtml(status)}</td>'
                  '</tr>';
            })
            .join();

    final logLines = payload.logs.isEmpty
        ? '<div style="color: rgba(0, 255, 65, 0.4); text-align: center; padding: 20px; font-style: italic;">No execution logs captured.</div>'
        : payload.logs
            .map((line) => '<div style="padding: 3px 0; border-bottom: 1px solid rgba(0, 255, 65, 0.05);">${_escapeHtml(line)}</div>')
            .join();

    // Format raw output for better presentation
    final formattedRawOutput = _formatRawOutput(payload.rawOutput);

    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LOUTE REPORT</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: dark;
    --bg: #000000;
    --panel: #000000;
    --ink: #00ff41;
    --muted: rgba(0, 255, 65, 0.5);
    --muted-glow: rgba(0, 255, 65, 0.1);
    --line: #00ff41;
    --accent: #00ff41;
    --warn: #ffbf00;
    --bad: #ff3b30;
    --good: #00ff41;
  }
  
  * {
    box-sizing: border-box;
  }
  
  body {
    margin: 0;
    padding: 0;
    font-family: 'JetBrains Mono', monospace;
    background-color: var(--bg);
    color: var(--ink);
    line-height: 1.5;
  }
  
  .wrap {
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px 24px;
    display: flex;
    flex-direction: column;
    gap: 32px;
  }
  
  /* Symmetrical Dashboard-style Centered Brand Header */
  .brand-header {
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding-bottom: 24px;
    border-bottom: 1px solid var(--line);
    margin-bottom: 8px;
  }
  
  .brand-logo {
    width: 80px;
    height: 80px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 16px;
  }
  
  .brand-logo img {
    width: 100%;
    height: 100%;
    object-fit: contain;
  }
  
  .brand-title {
    font-size: clamp(32px, 5vw, 48px);
    font-weight: 700;
    color: var(--ink);
    letter-spacing: 8px;
    margin: 0;
    text-transform: uppercase;
  }
  
  .brand-subtitle {
    font-size: clamp(14px, 2.5vw, 18px);
    color: var(--muted);
    margin-top: 8px;
    font-weight: 500;
  }
  
  .brand-engine-details {
    font-size: 12px;
    color: var(--muted);
    margin-top: 8px;
    opacity: 0.8;
  }
  
  .status-container {
    display: flex;
    justify-content: center;
    margin-top: 12px;
  }
  
  .status {
    padding: 8px 24px;
    border: 1px solid var(--line);
    text-transform: uppercase;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 2px;
    display: inline-block;
  }
  
  .status--completed {
    color: var(--ink);
    border-color: var(--ink);
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.2);
  }
  
  .status--failed {
    color: var(--bad);
    border-color: var(--bad);
    box-shadow: 0 0 10px rgba(255, 59, 48, 0.2);
  }
  
  .status--running {
    color: var(--warn);
    border-color: var(--warn);
    box-shadow: 0 0 10px rgba(255, 191, 0, 0.2);
  }
  
  /* Symmetrical Grid for Stats */
  .summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    width: 100%;
  }
  
  .summary-card {
    border: 1px solid var(--line);
    padding: 16px;
    background-color: var(--panel);
    text-align: center;
    transition: all 0.2s ease;
  }
  
  .summary-card:hover {
    box-shadow: 0 0 12px var(--muted-glow);
    border-color: var(--ink);
  }
  
  .summary-value {
    font-size: clamp(18px, 3vw, 22px);
    font-weight: 700;
    color: var(--ink);
  }
  
  .summary-label {
    font-size: 10px;
    text-transform: uppercase;
    color: var(--muted);
    letter-spacing: 2px;
    margin-top: 6px;
  }
  
  /* Symmetrical Content Panels */
  h2 {
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin: 16px 0 12px 0;
    color: var(--warn);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  h2::after {
    content: "";
    flex-grow: 1;
    height: 1px;
    background: rgba(0, 255, 65, 0.2);
  }
  
  .panel {
    border: 1px solid var(--line);
    background-color: var(--panel);
    padding: 20px;
    overflow-x: auto;
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
  }
  
  th {
    padding: 12px 14px;
    border-bottom: 1px solid var(--line);
    color: var(--muted);
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  
  td {
    padding: 10px 14px;
    border-bottom: 1px solid rgba(0, 255, 65, 0.15);
  }
  
  .raw-output {
    border: 1px solid var(--line);
    padding: 16px;
    background-color: #000000;
    font-size: 13px;
    max-height: 600px;
    overflow-y: auto;
    color: var(--ink);
  }
  
  /* Style tables inside raw output */
  .raw-output table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
  }
  
  .raw-output thead {
    background-color: rgba(0, 255, 65, 0.05);
  }
  
  .raw-output th {
    border: 1px solid var(--line);
    padding: 10px 12px;
    text-align: left;
    color: var(--warn);
    font-weight: bold;
    background-color: rgba(0, 255, 65, 0.03);
  }
  
  .raw-output td {
    border: 1px solid rgba(0, 255, 65, 0.2);
    padding: 8px 12px;
    color: #00ff41;
  }
  
  .raw-output tr:hover {
    background-color: rgba(0, 255, 65, 0.05);
  }
  
  /* Style headings inside raw output */
  .raw-output h3 {
    color: var(--warn);
    margin: 12px 0 8px 0;
    font-size: 14px;
    border-bottom: 1px solid rgba(255, 191, 0, 0.3);
    padding-bottom: 6px;
  }
  
  /* Style lists - convert to table-like appearance */
  .raw-output ul {
    list-style: none;
    padding: 0;
    margin: 8px 0;
  }
  
  .raw-output li {
    padding: 6px 10px;
    border-bottom: 1px solid rgba(0, 255, 65, 0.15);
    display: flex;
    align-items: center;
  }
  
  .raw-output li:hover {
    background-color: rgba(0, 255, 65, 0.05);
    color: var(--warn);
  }
  
  .raw-output li::before {
    content: "▸ ";
    color: var(--warn);
    margin-right: 8px;
    font-weight: bold;
  }
  
  .log-block {
    background-color: #000000;
    border: 1px solid var(--line);
    padding: 16px;
    max-height: 350px;
    overflow-y: auto;
    font-size: 12px;
    color: var(--ink);
  }
  
  /* Webkit custom scrollbars matching hacker aesthetics */
  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }
  ::-webkit-scrollbar-track {
    background: var(--bg);
  }
  ::-webkit-scrollbar-thumb {
    background: var(--muted);
    border-radius: 0;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: var(--ink);
  }
  
  .footer {
    margin-top: 32px;
    border-top: 1px solid var(--line);
    padding-top: 16px;
    font-size: 11px;
    color: var(--muted);
    text-align: center;
    letter-spacing: 1px;
  }
</style>
</head>
<body>
<div class="wrap">
  <!-- Perfect Centered Dashboard Header -->
  <div class="brand-header">
    <div class="brand-logo">
      <img src="data:image/png;base64,$logoBase64" alt="LOUTE LOGO" />
    </div>
    <h1 class="brand-title">LOUTE</h1>
    <div class="brand-subtitle">Autonomous Bug Bounty Framework</div>
    <div class="brand-engine-details">Native Rust Engine &bull; Flutter UI &bull; Zero External Dependencies</div>
    <div class="status-container">
      <div class="status $statusClass">${_escapeHtml(payload.status)}</div>
    </div>
  </div>

  <!-- Metadata -->
  <h2>Operation Parameters</h2>
  <div class="panel">
    <table style="border: 1px solid rgba(0, 255, 65, 0.2);">
      <tbody>
        <tr><td style="color: var(--muted); width: 220px; border-right: 1px solid rgba(0, 255, 65, 0.15);">Operation ID</td><td style="font-weight: bold; font-family: monospace;">${_escapeHtml(payload.id)}</td></tr>
        <tr><td style="color: var(--muted); border-right: 1px solid rgba(0, 255, 65, 0.15);">Target Action Name</td><td>${_escapeHtml(payload.actionName)} (${_escapeHtml(payload.actionId)})</td></tr>
        <tr><td style="color: var(--muted); border-right: 1px solid rgba(0, 255, 65, 0.15);">Module Category</td><td>${_escapeHtml(payload.moduleName)}</td></tr>
        <tr>
            <td style="color: var(--muted); border-right: 1px solid var(--muted-glow);">Execution Phase</td>
            <td>${payload.phaseName}</td>
          </tr>
          <tr>
            <td style="color: var(--muted); border-right: 1px solid var(--muted-glow);">System Version</td>
            <td style="font-family: monospace; color: var(--warn);">${payload.systemVersion}</td>
          </tr>
          <tr>
            <td style="color: var(--muted); border-right: 1px solid var(--muted-glow);">Final Exit Status</td><td style="font-weight: bold;">${_escapeHtml(payload.status)}</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Input Settings -->
  <h2>Action Input Variables</h2>
  <div class="panel">
    <table style="border: 1px solid rgba(0, 255, 65, 0.2);">
      <thead>
        <tr><th style="border-right: 1px solid rgba(0, 255, 65, 0.2);">Variable Key</th><th>Configured Value</th></tr>
      </thead>
      <tbody>
        $inputRows
      </tbody>
    </table>
  </div>

  <!-- Real-time Findings -->
  <h2>Detected Findings & Vulnerabilities</h2>
  <div class="panel">
    <table>
      <thead>
        <tr><th style="width: 50px;">#</th><th>Finding Type</th><th>Severity Level</th><th>Vulnerability Title</th><th>Description / Evidence</th><th>Verification Status</th></tr>
      </thead>
      <tbody>
        $findingsRows
      </tbody>
    </table>
  </div>

  <!-- Action RAW Output Console -->
  <h2>System Raw Standard Output</h2>
  <div class="panel raw-output">
$formattedRawOutput
  </div>

  <!-- Detailed logs -->
  <h2>Autonomous Execution Logs</h2>
  <div class="log-block">
    $logLines
  </div>

  <div class="footer">LOUTE FRAMEWORK &bull; ${_escapeHtml(payload.timestamp.toIso8601String())}</div>
</div>
</body>
</html>''';
  }

  static String _statusClass(String status) {
    final normalized = status.toLowerCase();
    if (normalized.contains('fail') || normalized.contains('error')) {
      return 'status--failed';
    }
    if (normalized.contains('run') || normalized.contains('progress')) {
      return 'status--running';
    }
    return 'status--completed';
  }

  static String _renderSeverityBadge(String severity) {
    final level = severity.isEmpty ? 'info' : severity.toLowerCase();
    String color = 'rgba(0, 255, 65, 0.5)';
    if (level == 'critical') color = '#ff3b30';
    if (level == 'high') color = '#ff9500';
    if (level == 'medium') color = '#ffbf00';
    if (level == 'low') color = '#00ff41';
    if (level == 'info') color = '#5ac8fa';
    return '<span class="sev-badge sev-badge--$level" data-severity="$level" '
        'style="padding: 4px 10px; border: 1px solid $color; color: $color; '
        'font-weight: bold; text-transform: uppercase; font-size: 11px; '
        'letter-spacing: 0.5px;">$level</span>';
  }

  static String _escapeHtml(String text) {
    return text
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
  }

  static String _safeString(Object? value) {
    if (value == null) return '';
    return value.toString();
  }

  static String _formatRawOutput(String rawOutput) {
    if (rawOutput.isEmpty) {
      return '<div style="color: rgba(0, 255, 65, 0.4); text-align: center; padding: 20px; font-style: italic;">No output captured.</div>';
    }
    
    // If it's already HTML with tables, return as-is (it will be styled by CSS)
    if (rawOutput.contains('<table') || rawOutput.contains('<thead') || rawOutput.contains('<tbody')) {
      return rawOutput;
    }
    
    // If it contains HTML lists, return as-is (will be styled by CSS)
    if (rawOutput.contains('<ul>') || rawOutput.contains('<li>')) {
      return rawOutput;
    }
    
    // If it contains HTML sections/divs, return as-is
    if (rawOutput.contains('<div') || rawOutput.contains('<section') || rawOutput.contains('<h2') || rawOutput.contains('<h3')) {
      return rawOutput;
    }
    
    // Otherwise, escape and wrap in pre-formatted text
    return '<pre style="margin: 0; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;">${_escapeHtml(rawOutput)}</pre>';
  }
}

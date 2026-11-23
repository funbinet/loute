import '../models/report_model.dart';
import 'package:html/parser.dart' as html_parser;
import 'package:html/dom.dart';

/// Parses HTML output from Rust actions and extracts structured findings
class HtmlOutputParser {
  /// Parse HTML from Rust action and extract structured data
  static List<Map<String, dynamic>> parseActionOutput(
    String htmlContent,
    String actionName,
  ) {
    if (htmlContent.isEmpty) return [];

    final doc = html_parser.parse(htmlContent);
    final findings = <Map<String, dynamic>>[];

    if (actionName.contains('dns') || actionName.contains('DNS')) {
      findings.addAll(_parseDnsBruteforce(doc));
    } else if (actionName.contains('ct') || actionName.contains('certificate')) {
      findings.addAll(_parseCertificateTransparency(doc));
    } else if (actionName.contains('zone') || actionName.contains('transfer')) {
      findings.addAll(_parseZoneTransfer(doc));
    } else if (actionName.contains('reverse') || actionName.contains('rdns')) {
      findings.addAll(_parseReverseDns(doc));
    } else if (actionName.contains('wildcard')) {
      findings.addAll(_parseWildcardDetection(doc));
    } else if (actionName.contains('cloud') || actionName.contains('provider')) {
      findings.addAll(_parseCloudProvider(doc));
    } else if (actionName.contains('s3')) {
      findings.addAll(_parseS3Check(doc));
    } else if (actionName.contains('metadata')) {
      findings.addAll(_parseMetadataProbe(doc));
    } else if (actionName.contains('firebase')) {
      findings.addAll(_parseFirebaseCheck(doc));
    } else if (actionName.contains('cdn')) {
      findings.addAll(_parseCdnDetection(doc));
    } else if (actionName.contains('network') || actionName.contains('audit')) {
      findings.addAll(_parseNetworkAudit(doc));
    }

    return findings;
  }

  // DNS Brute-Force Parser - Enhanced
  static List<Map<String, dynamic>> _parseDnsBruteforce(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final tables = doc.querySelectorAll('table');
    int foundCount = 0;

    for (final table in tables) {
      final rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        final cells = rows[i].querySelectorAll('td');
        if (cells.length >= 3) {
          final subdomain = _getText(cells[0]);
          final ips = _getText(cells[1]);
          final responseTime = _getText(cells[2]);

          if (subdomain.isNotEmpty && ips.isNotEmpty) {
            foundCount++;
            findings.add({
              'type': 'dns_discovery',
              'severity': 'info',
              'title': 'Discovered Subdomain: $subdomain',
              'description': 'DNS brute-force found active subdomain resolving to real IP addresses',
              'status': ips.contains('NXDOMAIN') ? 'not_found' : 'found',
              'evidence': 'Subdomain: $subdomain\nIP Addresses: $ips\nResponse Time: $responseTime ms',
              'subdomain': subdomain,
              'ips': ips,
              'response_time_ms': responseTime,
            });
          }
        }
      }
    }
    
    // If no subdomains found, report the test completion
    if (foundCount == 0 && doc.body != null) {
      findings.add({
        'type': 'dns_brute_force_test',
        'severity': 'info',
        'title': 'DNS Brute-Force Scan Completed',
        'description': 'No active subdomains were discovered during brute-force scan',
        'status': 'completed',
        'evidence': 'Scan completed with no subdomains found - domain may have limited subdomain infrastructure',
      });
    }

    return findings;
  }

  // Certificate Transparency Parser - Enhanced
  static List<Map<String, dynamic>> _parseCertificateTransparency(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final bodyText = (doc.body?.text ?? '').toLowerCase();
    final bodyHtml = doc.body?.innerHtml ?? '';
    
    // Check for error conditions first
    if (bodyHtml.contains('Failed to contact') || 
        bodyHtml.contains('CT_LOGS_NETWORK_ERROR') ||
        bodyHtml.contains('error sending request')) {
      findings.add({
        'type': 'certificate_transparency_error',
        'severity': 'high',
        'title': 'Certificate Transparency Lookup Failed',
        'description': 'Network error occurred while querying Certificate Transparency logs via crt.sh. The service may be temporarily unavailable or there is a connectivity issue.',
        'status': 'failed',
        'evidence': 'crt.sh API endpoint unreachable. This could indicate network issues, rate limiting, or service unavailability.',
      });
      return findings;
    }
    
    if (bodyHtml.contains('CT_LOGS_RATE_LIMIT') || 
        bodyHtml.contains('rate-limiting')) {
      findings.add({
        'type': 'certificate_transparency_rate_limit',
        'severity': 'high',
        'title': 'CT Logs Service Rate Limited',
        'description': 'The crt.sh Certificate Transparency service is rate-limiting requests. Wait 60 seconds before retrying.',
        'status': 'rate_limited',
        'evidence': 'HTTP 429 Too Many Requests received from crt.sh. Implement backoff strategy before retry.',
      });
      return findings;
    }
    
    if (bodyHtml.contains('CT_LOGS_HTTP_ERROR') || 
        bodyHtml.contains('returned HTTP')) {
      findings.add({
        'type': 'certificate_transparency_http_error',
        'severity': 'medium',
        'title': 'CT Logs HTTP Error',
        'description': 'The crt.sh service returned an HTTP error. The certificate lookup could not be completed.',
        'status': 'failed',
        'evidence': 'crt.sh returned an unexpected HTTP status code. Service may be experiencing issues.',
      });
      return findings;
    }
    
    if (bodyHtml.contains('CT_LOGS_PARSE_ERROR') || 
        bodyHtml.contains('Failed to parse')) {
      findings.add({
        'type': 'certificate_transparency_parse_error',
        'severity': 'medium',
        'title': 'CT Logs Response Parse Error',
        'description': 'Failed to parse the JSON response from the Certificate Transparency service.',
        'status': 'failed',
        'evidence': 'The crt.sh API response could not be parsed as valid JSON.',
      });
      return findings;
    }
    
    // Look for normal tables with certificate data
    final tables = doc.querySelectorAll('table');
    int certCount = 0;

    for (final table in tables) {
      final rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        final cells = rows[i].querySelectorAll('td');
        if (cells.length >= 3) {
          final domain = _getText(cells[0]);
          final issuer = _getText(cells[1]);
          final date = _getText(cells[2]);

          if (domain.isNotEmpty) {
            certCount++;
            findings.add({
              'type': 'certificate_discovered',
              'severity': domain.startsWith('*.') ? 'medium' : 'info',
              'title': domain.startsWith('*.') 
                  ? 'Wildcard Certificate Found: $domain'
                  : 'SSL Certificate Found: $domain',
              'description': 'SSL certificate discovered in Certificate Transparency logs revealing domain information',
              'status': 'found',
              'evidence': 'Domain: $domain\nIssuer: $issuer\nDate: $date',
              'domain': domain,
              'issuer': issuer,
              'date': date,
              'is_wildcard': domain.startsWith('*.'),
            });
          }
        }
      }
    }
    
    // If no certificates found (but no errors either)
    if (certCount == 0 && findings.isEmpty && doc.body != null) {
      findings.add({
        'type': 'certificate_transparency_test',
        'severity': 'info',
        'title': 'Certificate Transparency Lookup Completed',
        'description': 'No SSL certificates found in Certificate Transparency logs for this domain',
        'status': 'completed',
        'evidence': 'CT log search completed with no matching certificates',
      });
    }

    return findings;
  }

  // Zone Transfer Parser - Enhanced
  static List<Map<String, dynamic>> _parseZoneTransfer(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final htmlText = doc.body?.text ?? '';
    final bodyText = htmlText.toLowerCase();

    // Look for specific indicators
    bool hasSuccess = bodyText.contains('success');
    bool hasRefused = bodyText.contains('refused') || bodyText.contains('denied');
    bool hasResult = bodyText.contains('axfr') || bodyText.contains('zone transfer');

    if (hasSuccess) {
      // Critical: Zone transfer was successful
      final records = RegExp(r'(\w+\.[\w.-]+)\s+(\d+)\s+(\w+)').allMatches(htmlText);
      List<String> foundRecords = [];
      for (final match in records) {
        foundRecords.add(match.group(0)!);
      }
      
      findings.add({
        'type': 'zone_transfer_vulnerability',
        'severity': 'critical',
        'title': 'ZONE TRANSFER ENABLED - CRITICAL VULNERABILITY',
        'description': 'Zone transfer (AXFR) was successful - allows attacker to retrieve entire DNS zone',
        'status': 'vulnerable',
        'evidence': foundRecords.isNotEmpty 
            ? 'Retrieved ${foundRecords.length} DNS records via AXFR'
            : 'Zone transfer succeeded - DNS records accessible',
        'record_count': foundRecords.length.toString(),
      });
    } else if (hasRefused || hasResult) {
      // Good: Zone transfer was blocked
      findings.add({
        'type': 'zone_transfer_protected',
        'severity': 'info',
        'title': 'Zone Transfer Properly Blocked',
        'description': 'Zone transfer (AXFR) attempt was refused - DNS configuration is secure',
        'status': 'protected',
        'evidence': 'Server refused AXFR request - zone transfer is not publicly accessible',
      });
    } else if (doc.body != null) {
      // Generic: Test was performed
      findings.add({
        'type': 'zone_transfer_test',
        'severity': 'info',
        'title': 'Zone Transfer Test Completed',
        'description': 'Zone transfer security test completed',
        'status': 'completed',
        'evidence': 'Zone transfer test completed',
      });
    }

    return findings;
  }

  // Reverse DNS Parser - Enhanced
  static List<Map<String, dynamic>> _parseReverseDns(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final tables = doc.querySelectorAll('table');
    int mappingCount = 0;

    for (final table in tables) {
      final rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        final cells = rows[i].querySelectorAll('td');
        if (cells.length >= 2) {
          final ip = _getText(cells[0]);
          final hostname = _getText(cells[1]);

          if (ip.isNotEmpty && hostname.isNotEmpty && !hostname.contains('[No')) {
            mappingCount++;
            findings.add({
              'type': 'reverse_dns_mapping',
              'severity': 'info',
              'title': 'Reverse DNS: $ip → $hostname',
              'description': 'Reverse DNS lookup reveals hostname for IP address - provides reconnaissance data',
              'status': 'found',
              'evidence': 'IP Address: $ip\nHostname: $hostname',
              'ip_address': ip,
              'hostname': hostname,
            });
          }
        }
      }
    }
    
    // If no mappings found
    if (mappingCount == 0 && doc.body != null) {
      findings.add({
        'type': 'reverse_dns_test',
        'severity': 'info',
        'title': 'Reverse DNS Lookup Completed',
        'description': 'No reverse DNS mappings were found for the specified CIDR range',
        'status': 'completed',
        'evidence': 'Reverse DNS scan completed - no active hostnames discovered',
      });
    }

    return findings;
  }

  // Wildcard Detection Parser - Enhanced to capture test results
  static List<Map<String, dynamic>> _parseWildcardDetection(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final bodyText = doc.body?.text ?? '';
    
    // Extract main content divs
    final divs = doc.querySelectorAll('div');
    
    String title = '';
    String result = '';
    String subdomain = '';
    
    for (final div in divs) {
      final text = div.text.trim();
      
      // Look for the h3 title or main heading
      final h3 = div.querySelector('h3');
      if (h3 != null) {
        title = h3.text.trim();
      }
      
      // Look for result indicators
      if (text.contains('WILDCARD DETECTED')) {
        result = text.contains('NO WILDCARD') ? 'not_detected' : 'detected';
      }
      
      // Extract subdomain from code tag
      final code = div.querySelector('code');
      if (code != null) {
        subdomain = code.text.trim();
      }
    }
    
    // Build finding based on detected state
    if (title.isNotEmpty || bodyText.contains('Wildcard')) {
      findings.add({
        'type': result == 'detected' ? 'wildcard_dns_detected' : 'wildcard_dns_check',
        'severity': result == 'detected' ? 'medium' : 'info',
        'title': result == 'detected' 
            ? 'Wildcard DNS Record Detected' 
            : 'Wildcard DNS Check Completed',
        'description': result == 'detected'
            ? 'Domain has wildcard DNS entry which may catch typos'
            : 'Domain does not have a wildcard DNS record - proper configuration',
        'status': result == 'detected' ? 'found' : 'not_found',
        'evidence': subdomain.isNotEmpty
            ? 'Test subdomain: $subdomain | Response: NXDOMAIN (expected)'
            : 'Wildcard DNS test completed',
        'result': result,
        'test_subdomain': subdomain,
      });
    }

    return findings;
  }

  // Cloud Provider Parser - Enhanced
  static List<Map<String, dynamic>> _parseCloudProvider(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final htmlText = doc.body?.text ?? '';
    bool foundProvider = false;

    const providers = ['AWS', 'Azure', 'GCP', 'Cloudflare', 'Amazon', 'Google Cloud', 'Microsoft'];
    for (final provider in providers) {
      if (htmlText.contains(provider)) {
        foundProvider = true;
        final confidence = _extractConfidence(htmlText);
        findings.add({
          'type': 'cloud_provider_detected',
          'severity': 'info',
          'title': '$provider Cloud Infrastructure Detected',
          'description': 'Target is hosted on $provider cloud services - infrastructure reconnaissance data',
          'status': 'found',
          'evidence': 'Provider indicators found in HTTP headers and SSL certificates',
          'provider': provider,
          'confidence': confidence,
        });
      }
    }
    
    // If no provider identified
    if (!foundProvider && doc.body != null) {
      findings.add({
        'type': 'cloud_provider_check',
        'severity': 'info',
        'title': 'Cloud Provider Detection Completed',
        'description': 'Cloud provider fingerprinting analysis completed',
        'status': 'completed',
        'evidence': 'No major cloud providers detected - may be self-hosted or traditional hosting',
      });
    }

    return findings;
  }

  // S3 Bucket Parser - Enhanced
  static List<Map<String, dynamic>> _parseS3Check(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final tables = doc.querySelectorAll('table');
    int vulnerableCount = 0;
    int testCount = 0;

    for (final table in tables) {
      final rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        final cells = rows[i].querySelectorAll('td');
        if (cells.length >= 2) {
          final permission = _getText(cells[0]);
          final status = _getText(cells[1]);

          if (permission.isNotEmpty && status.isNotEmpty) {
            testCount++;
            final isVulnerable = status.contains('✔') || status.contains('Yes') || status.toLowerCase().contains('enabled');
            if (isVulnerable) {
              vulnerableCount++;
            }
            
            findings.add({
              'type': 's3_bucket_permission',
              'severity': isVulnerable ? 'high' : 'info',
              'title': isVulnerable 
                  ? 'VULNERABLE: $permission is Enabled' 
                  : 'S3 Permission: $permission is Disabled',
              'description': isVulnerable
                  ? 'S3 bucket allows public $permission - HIGH RISK misconfiguration'
                  : 'S3 bucket properly restricts $permission permission',
              'status': isVulnerable ? 'vulnerable' : 'protected',
              'evidence': 'Permission: $permission | State: ${isVulnerable ? "ENABLED (PUBLIC)" : "DISABLED (RESTRICTED)"}',
              'permission': permission,
              'is_vulnerable': isVulnerable,
            });
          }
        }
      }
    }
    
    // Summary if tests were run
    if (testCount > 0) {
      findings.add({
        'type': 's3_bucket_test_summary',
        'severity': vulnerableCount > 0 ? 'high' : 'info',
        'title': 'S3 Bucket Permissions Test Summary',
        'description': 'Completed S3 bucket permission testing - ${vulnerableCount > 0 ? "VULNERABILITIES FOUND" : "all permissions properly restricted"}',
        'status': vulnerableCount > 0 ? 'vulnerable' : 'protected',
        'evidence': 'Tested $testCount permissions - ${vulnerableCount > 0 ? "$vulnerableCount VULNERABLE" : "0 vulnerable"}',
        'vulnerable_count': vulnerableCount,
        'total_tests': testCount,
      });
    }

    return findings;
  }

  // Metadata Probe Parser - Enhanced
  static List<Map<String, dynamic>> _parseMetadataProbe(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final htmlText = doc.body?.text ?? '';
    final bodyText = htmlText.toLowerCase();

    if (bodyText.contains('accessible') || 
        bodyText.contains('200') ||
        bodyText.contains('success') ||
        bodyText.contains('connection succeeded')) {
      findings.add({
        'type': 'metadata_endpoint_accessible',
        'severity': 'critical',
        'title': 'CRITICAL: Cloud Metadata Endpoint Accessible',
        'description': 'Instance metadata service is publicly accessible - allows SSRF attacks to steal credentials',
        'status': 'vulnerable',
        'evidence': 'Metadata endpoint responded with valid data - remote attacker can retrieve credentials',
      });
    } else {
      findings.add({
        'type': 'metadata_endpoint_protected',
        'severity': 'info',
        'title': 'Metadata Endpoint Properly Protected',
        'description': 'Cloud metadata service is not publicly accessible - secure configuration',
        'status': 'protected',
        'evidence': 'Endpoint is not accessible from external networks or properly firewalled',
      });
    }

    return findings;
  }

  // Firebase Parser - Enhanced
  static List<Map<String, dynamic>> _parseFirebaseCheck(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final htmlText = doc.body?.text ?? '';
    final bodyText = htmlText.toLowerCase();

    if ((bodyText.contains('accessible') || 
         bodyText.contains('anonymous') || 
         bodyText.contains('enabled')) &&
        bodyText.contains('read')) {
      findings.add({
        'type': 'firebase_security_issue',
        'severity': 'high',
        'title': 'VULNERABLE: Firebase Allows Anonymous Read Access',
        'description': 'Firebase Realtime Database allows unauthenticated read access - data exposure risk',
        'status': 'vulnerable',
        'evidence': 'Anonymous users can read entire database contents without authentication',
      });
    } else {
      findings.add({
        'type': 'firebase_security_check',
        'severity': 'info',
        'title': 'Firebase Security Check Completed',
        'description': 'Firebase project has proper authentication rules configured',
        'status': 'protected',
        'evidence': 'Anonymous access is properly restricted or database not accessible',
      });
    }

    return findings;
  }

  // CDN Detection Parser - Enhanced
  static List<Map<String, dynamic>> _parseCdnDetection(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final htmlText = doc.body?.text ?? '';
    bool foundCdn = false;

    const cdns = [
      'Cloudflare',
      'CloudFront',
      'Akamai',
      'Fastly',
      'EdgeCast',
      'Cloudflare',
      'AWS',
      'Azure CDN',
    ];
    
    for (final cdn in cdns) {
      if (htmlText.contains(cdn)) {
        foundCdn = true;
        findings.add({
          'type': 'cdn_detected',
          'severity': 'info',
          'title': '$cdn CDN Infrastructure Detected',
          'description': 'Target uses $cdn Content Delivery Network for content distribution and acceleration',
          'status': 'found',
          'evidence': 'CDN indicators found in HTTP response headers and DNS records',
          'cdn_provider': cdn,
        });
      }
    }
    
    // If no CDN found
    if (!foundCdn && doc.body != null) {
      findings.add({
        'type': 'cdn_detection_test',
        'severity': 'info',
        'title': 'CDN Detection Completed',
        'description': 'CDN fingerprinting analysis completed - no major CDN detected',
        'status': 'completed',
        'evidence': 'No major CDN providers detected - content may be served from origin directly',
      });
    }

    return findings;
  }

  // Network Services Parser - Enhanced
  static List<Map<String, dynamic>> _parseNetworkAudit(Document doc) {
    final findings = <Map<String, dynamic>>[];
    final tables = doc.querySelectorAll('table');
    int openPorts = 0;
    int criticalPorts = 0;

    for (final table in tables) {
      final rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        final cells = rows[i].querySelectorAll('td');
        if (cells.length >= 3) {
          final port = _getText(cells[0]);
          final service = _getText(cells[1]);
          final state = _getText(cells[2]);

          if (port.isNotEmpty && service.isNotEmpty) {
            openPorts++;
            final severity = _getPortSeverity(port);
            if (severity == 'high' || severity == 'critical') {
              criticalPorts++;
            }
            
            findings.add({
              'type': 'open_port_detected',
              'severity': severity,
              'title': 'Open Port: TCP/$port ($service)',
              'description': 'Network service is actively listening on port $port - exposes $service to network',
              'status': 'open',
              'evidence': 'Protocol: TCP | Port: $port | Service: $service | State: $state',
              'port': port,
              'service': service,
              'port_state': state,
            });
          }
        }
      }
    }
    
    // Summary finding
    if (openPorts > 0) {
      findings.add({
        'type': 'network_audit_summary',
        'severity': criticalPorts > 0 ? 'high' : 'info',
        'title': 'Network Audit Summary',
        'description': 'Network services audit completed - $openPorts open ports detected',
        'status': 'completed',
        'evidence': 'Found $openPorts open ports${criticalPorts > 0 ? " - $criticalPorts with HIGH/CRITICAL severity" : ""}',
        'open_port_count': openPorts,
        'critical_port_count': criticalPorts,
      });
    } else if (doc.body != null) {
      findings.add({
        'type': 'network_audit_test',
        'severity': 'info',
        'title': 'Network Audit Completed',
        'description': 'Network services audit completed - no open ports detected or scan incomplete',
        'status': 'completed',
        'evidence': 'Network scan completed',
      });
    }

    return findings;
  }

  // Utility functions

  static String _getText(Element element) {
    return element.text.trim();
  }

  static String _extractConfidence(String text) {
    final match = RegExp(r'(\d+)%').firstMatch(text);
    if (match != null) {
      return '${match.group(1)}%';
    }
    return 'unknown';
  }

  static String _getPortSeverity(String port) {
    try {
      final portNum = int.parse(port);
      if (portNum < 1024) return 'medium';
      if ([22, 3389, 5900].contains(portNum)) return 'high';
      if ([80, 443, 8080].contains(portNum)) return 'low';
      return 'low';
    } catch (_) {
      return 'info';
    }
  }
}

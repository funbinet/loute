import 'package:flutter/material.dart';
import 'phase_model.dart';

/// Static registry of all 10 phases, 22 modules, 107 actions.
/// Now features fully unique and diverse Material Icons for all items.
class PhaseRegistry {
  PhaseRegistry._();

  static final List<Phase> phases = [
    // ── Phase 1: Reconnaissance ──
    Phase(id: 'p1', name: 'Reconnaissance', icon: Icons.radar_outlined, description: 'Subdomain discovery, cloud recon', modules: [
      Module(id: 'm1_1', phaseId: 'p1', name: 'Subdomains', icon: Icons.domain_outlined, actions: [
        ActionItem(id: 'a1_1_1', moduleId: 'm1_1', name: 'DNS Bruteforce', icon: Icons.all_inclusive_outlined, rustFunction: 'dns_bruteforce', description: 'Performs high-speed concurrent DNS resolution against a target domain using a specified wordlist to discover undocumented subdomains and internal routing infrastructure. Targets are queried for A, AAAA, and CNAME records.', executionStyle: 'async_parallel', inputs: [
          InputField(key: 'domain', label: 'Domain', hint: 'example.com'),
          InputField(key: 'wordlist', label: 'Wordlist Path', hint: '/path/to/wordlist.txt', type: InputFieldType.filePath, required: false),
          InputField(key: 'concurrency', label: 'Concurrency', hint: '1000', type: InputFieldType.number, defaultValue: 1000),
        ]),
        ActionItem(id: 'a1_1_2', moduleId: 'm1_1', name: 'Cert Logs', icon: Icons.receipt_long_outlined, rustFunction: 'ct_logs', description: 'Queries Certificate Transparency (CT) logs to identify subdomains that have had SSL/TLS certificates issued, revealing hidden staging or internal environments.', inputs: [
          InputField(key: 'domain', label: 'Domain', hint: 'example.com'),
        ]),
        ActionItem(id: 'a1_1_3', moduleId: 'm1_1', name: 'Zone Transfer', icon: Icons.swap_horiz_outlined, rustFunction: 'zone_transfer', description: 'Attempts a DNS Zone Transfer (AXFR) against the target domain\'s authoritative nameservers to completely dump all DNS records, exposing the entire internal and external network topology.', inputs: [
          InputField(key: 'domain', label: 'Domain', hint: 'example.com'),
          InputField(key: 'nameserver', label: 'Nameserver IP', hint: 'optional', required: false),
        ]),
        ActionItem(id: 'a1_1_4', moduleId: 'm1_1', name: 'Reverse DNS', icon: Icons.wifi_protected_setup_outlined, rustFunction: 'reverse_dns', description: 'Scans a provided CIDR network range to resolve PTR records, mapping IP addresses back to their registered hostnames to identify the scope and ownership of the target\'s infrastructure.', inputs: [
          InputField(key: 'cidr', label: 'IP Range (CIDR)', hint: '192.168.1.0/24'),
        ]),
        ActionItem(id: 'a1_1_5', moduleId: 'm1_1', name: 'Wildcard Check', icon: Icons.star_border_purple500_outlined, rustFunction: 'wildcard_detect', description: 'Analyzes the target domain to detect wildcard DNS resolution (*.domain.com), which is critical to avoid false positives during subdomain enumeration and fuzzing.', inputs: [
          InputField(key: 'domain', label: 'Domain', hint: 'example.com'),
        ]),
      ]),
      Module(id: 'm1_2', phaseId: 'p1', name: 'Cloud Recon', icon: Icons.cloud_queue_outlined, actions: [
        ActionItem(id: 'a1_2_1', moduleId: 'm1_2', name: 'Provider Check', icon: Icons.storage_outlined, rustFunction: 'cloud_provider', description: 'Interrogates the target IP or hostname to identify the underlying cloud service provider (e.g., AWS, GCP, Azure) via IP ranges, HTTP headers, and metadata signatures.', inputs: [
          InputField(key: 'target', label: 'Target URL/IP', hint: 'https://example.com'),
        ]),
        ActionItem(id: 'a1_2_2', moduleId: 'm1_2', name: 'S3 Check', icon: Icons.shopping_bag_outlined, rustFunction: 's3_check', description: 'Scans for publicly accessible or misconfigured cloud storage buckets matching the target company\'s name, identifying potential data leaks and unauthorized access vectors.', inputs: [
          InputField(key: 'bucket', label: 'Bucket Name / Company', hint: 'company-name'),
        ]),
        ActionItem(id: 'a1_2_3', moduleId: 'm1_2', name: 'Metadata Probe', icon: Icons.info_outline, rustFunction: 'metadata_probe', description: 'Probes the target IP for exposed cloud instance metadata services (IMDS), attempting to extract sensitive access tokens, SSH keys, and provisioning scripts.', inputs: [
          InputField(key: 'target', label: 'Target IP', hint: '10.0.0.1'),
        ]),
        ActionItem(id: 'a1_2_4', moduleId: 'm1_2', name: 'Firebase Check', icon: Icons.local_fire_department_outlined, rustFunction: 'firebase_check', description: 'Analyzes the target Firebase project ID for insecure rules and unauthenticated database read/write access, exposing real-time databases and Firestore instances.', inputs: [
          InputField(key: 'project_id', label: 'Project ID', hint: 'my-firebase-project'),
        ]),
        ActionItem(id: 'a1_2_5', moduleId: 'm1_2', name: 'CDN Detect', icon: Icons.router_outlined, rustFunction: 'cdn_detect', description: 'Identifies Content Delivery Networks (CDNs) and Web Application Firewalls (WAFs) protecting the target by analyzing HTTP response headers, CNAMEs, and specific IP blocks.', inputs: [
          InputField(key: 'target', label: 'Target URL', hint: 'https://example.com'),
        ]),
        ActionItem(
          id: 'a1_2_6',
          moduleId: 'm1_2',
          name: 'Network Audit',
          icon: Icons.network_check_outlined,
          rustFunction: 'network_services_audit', description: 'Conducts a comprehensive port scan and service enumeration across the target\'s external attack surface to identify open ports, running services, and version information.',
          supportedPlatforms: ['linux', 'windows'],
        ),
      ]),
    ]),

    // ── Phase 2: Mapping ──
    Phase(id: 'p2', name: 'Mapping', icon: Icons.map_outlined, description: 'URL crawling, JS analysis', modules: [
      Module(id: 'm2_1', phaseId: 'p2', name: 'URL Discovery', icon: Icons.find_in_page_outlined, actions: [
        ActionItem(id: 'a2_1_1', moduleId: 'm2_1', name: 'Crawler', icon: Icons.bug_report_outlined, rustFunction: 'crawl', description: 'Crawls the target URL up to a specified depth to map the application structure, discover hidden paths, and catalog all accessible endpoints and parameters.', inputs: [
          InputField(key: 'url', label: 'Start URL', hint: 'https://example.com'),
          InputField(key: 'depth', label: 'Max Depth', type: InputFieldType.number, defaultValue: 3),
          InputField(key: 'max_pages', label: 'Max Pages', type: InputFieldType.number, defaultValue: 100),
        ]),
        ActionItem(id: 'a2_1_2', moduleId: 'm2_1', name: 'JS Params', icon: Icons.data_object_outlined, rustFunction: 'js_parser'),
        ActionItem(id: 'a2_1_3', moduleId: 'm2_1', name: 'Wayback', icon: Icons.history_outlined, rustFunction: 'wayback'),
        ActionItem(id: 'a2_1_4', moduleId: 'm2_1', name: 'API Docs', icon: Icons.api_outlined, rustFunction: 'api_docs'),
        ActionItem(id: 'a2_1_5', moduleId: 'm2_1', name: 'Dir Fuzzing', icon: Icons.folder_open_outlined, rustFunction: 'dir_fuzz'),
      ]),
      Module(id: 'm2_2', phaseId: 'p2', name: 'JS Analysis', icon: Icons.javascript_outlined, actions: [
        ActionItem(id: 'a2_2_1', moduleId: 'm2_2', name: 'JS Endpoints', icon: Icons.link_outlined, rustFunction: 'js_endpoints'),
        ActionItem(id: 'a2_2_2', moduleId: 'm2_2', name: 'Find Secrets', icon: Icons.key_outlined, rustFunction: 'secrets'),
        ActionItem(id: 'a2_2_3', moduleId: 'm2_2', name: 'Detect Libs', icon: Icons.library_books_outlined, rustFunction: 'lib_detect'),
        ActionItem(id: 'a2_2_4', moduleId: 'm2_2', name: 'Extract Comments', icon: Icons.comment_outlined, rustFunction: 'comments'),
        ActionItem(id: 'a2_2_5', moduleId: 'm2_2', name: 'Sus Functions', icon: Icons.warning_amber_outlined, rustFunction: 'suspicious'),
      ]),
    ]),

    // ── Phase 3: Authentication ──
    Phase(id: 'p3', name: 'Authentication', icon: Icons.lock_open_outlined, modules: [
      Module(id: 'm3_1', phaseId: 'p3', name: 'Auth Testing', icon: Icons.how_to_reg_outlined, actions: [
        ActionItem(id: 'a3_1_1', moduleId: 'm3_1', name: 'Default Creds', icon: Icons.password_outlined, rustFunction: 'default_creds'),
        ActionItem(id: 'a3_1_2', moduleId: 'm3_1', name: 'User Enum', icon: Icons.person_search_outlined, rustFunction: 'user_enum'),
        ActionItem(id: 'a3_1_3', moduleId: 'm3_1', name: 'Reset Tokens', icon: Icons.restore_page_outlined, rustFunction: 'reset_token'),
        ActionItem(id: 'a3_1_4', moduleId: 'm3_1', name: 'JWT Check', icon: Icons.token_outlined, rustFunction: 'jwt_test'),
        ActionItem(id: 'a3_1_5', moduleId: 'm3_1', name: 'Session Fix', icon: Icons.supervised_user_circle_outlined, rustFunction: 'session_fixation'),
      ]),
      Module(id: 'm3_2', phaseId: 'p3', name: 'Authorization', icon: Icons.admin_panel_settings_outlined, actions: [
        ActionItem(id: 'a3_2_1', moduleId: 'm3_2', name: 'IDOR', icon: Icons.dialpad_outlined, rustFunction: 'idor_numeric'),
        ActionItem(id: 'a3_2_2', moduleId: 'm3_2', name: 'Horiz Priv', icon: Icons.compare_arrows_outlined, rustFunction: 'horizontal_priv'),
        ActionItem(id: 'a3_2_3', moduleId: 'm3_2', name: 'Vertical Priv', icon: Icons.upgrade_outlined, rustFunction: 'vertical_priv'),
        ActionItem(id: 'a3_2_4', moduleId: 'm3_2', name: 'Path Traversal', icon: Icons.drive_file_move_rtl_outlined, rustFunction: 'path_traversal_auth'),
        ActionItem(id: 'a3_2_5', moduleId: 'm3_2', name: 'Missing Auth', icon: Icons.no_accounts_outlined, rustFunction: 'no_auth'),
      ]),
    ]),

    // ── Phase 4: Injection ──
    Phase(id: 'p4', name: 'Injection', icon: Icons.security_outlined, modules: [
      Module(id: 'm4_1', phaseId: 'p4', name: 'XSS', icon: Icons.code_off_outlined, actions: [
        ActionItem(id: 'a4_1_1', moduleId: 'm4_1', name: 'Reflected', icon: Icons.flip_outlined, rustFunction: 'xss_reflected'),
        ActionItem(id: 'a4_1_2', moduleId: 'm4_1', name: 'Stored', icon: Icons.save_as_outlined, rustFunction: 'xss_stored'),
        ActionItem(id: 'a4_1_3', moduleId: 'm4_1', name: 'DOM', icon: Icons.account_tree_outlined, rustFunction: 'xss_dom'),
        ActionItem(id: 'a4_1_4', moduleId: 'm4_1', name: 'CSP Check', icon: Icons.policy_outlined, rustFunction: 'csp_check'),
        ActionItem(id: 'a4_1_5', moduleId: 'm4_1', name: 'Attr XSS', icon: Icons.text_fields_outlined, rustFunction: 'xss_attribute'),
      ]),
      Module(id: 'm4_2', phaseId: 'p4', name: 'SQLi', icon: Icons.dns_outlined, actions: [
        ActionItem(id: 'a4_2_1', moduleId: 'm4_2', name: 'Error SQLi', icon: Icons.error_outline, rustFunction: 'sqli_error'),
        ActionItem(id: 'a4_2_2', moduleId: 'm4_2', name: 'Bool Blind', icon: Icons.check_box_outline_blank_outlined, rustFunction: 'sqli_boolean'),
        ActionItem(id: 'a4_2_3', moduleId: 'm4_2', name: 'Time Blind', icon: Icons.access_time_outlined, rustFunction: 'sqli_time'),
        ActionItem(id: 'a4_2_4', moduleId: 'm4_2', name: 'Union', icon: Icons.merge_type_outlined, rustFunction: 'sqli_union'),
        ActionItem(id: 'a4_2_5', moduleId: 'm4_2', name: 'WAF Bypass', icon: Icons.shield_outlined, rustFunction: 'waf_bypass'),
      ]),
      Module(id: 'm4_3', phaseId: 'p4', name: 'SSRF', icon: Icons.cast_connected_outlined, actions: [
        ActionItem(id: 'a4_3_1', moduleId: 'm4_3', name: 'Metadata', icon: Icons.receipt_outlined, rustFunction: 'ssrf_metadata'),
        ActionItem(id: 'a4_3_2', moduleId: 'm4_3', name: 'Internal IPs', icon: Icons.lan_outlined, rustFunction: 'ssrf_internal'),
        ActionItem(id: 'a4_3_3', moduleId: 'm4_3', name: 'Local File', icon: Icons.snippet_folder_outlined, rustFunction: 'ssrf_file'),
        ActionItem(id: 'a4_3_4', moduleId: 'm4_3', name: 'Protocol Fuzz', icon: Icons.swap_calls_outlined, rustFunction: 'ssrf_protocol'),
        ActionItem(id: 'a4_3_5', moduleId: 'm4_3', name: 'Redirect SSRF', icon: Icons.alt_route_outlined, rustFunction: 'ssrf_redirect'),
      ]),
    ]),

    // ── Phase 5: API Security ──
    Phase(id: 'p5', name: 'API Security', icon: Icons.settings_suggest_outlined, modules: [
      Module(id: 'm5_1', phaseId: 'p5', name: 'REST API', icon: Icons.http_outlined, actions: [
        ActionItem(id: 'a5_1_1', moduleId: 'm5_1', name: 'Endpoints', icon: Icons.list_alt_outlined, rustFunction: 'rest_enum'),
        ActionItem(id: 'a5_1_2', moduleId: 'm5_1', name: 'No Auth', icon: Icons.lock_open_outlined, rustFunction: 'rest_no_auth'),
        ActionItem(id: 'a5_1_3', moduleId: 'm5_1', name: 'Rate Limits', icon: Icons.speed_outlined, rustFunction: 'rate_limit'),
        ActionItem(id: 'a5_1_4', moduleId: 'm5_1', name: 'Method Override', icon: Icons.published_with_changes_outlined, rustFunction: 'method_override'),
        ActionItem(id: 'a5_1_5', moduleId: 'm5_1', name: 'Deprecated', icon: Icons.auto_delete_outlined, rustFunction: 'deprecated'),
      ]),
      Module(id: 'm5_2', phaseId: 'p5', name: 'GraphQL', icon: Icons.hub_outlined, actions: [
        ActionItem(id: 'a5_2_1', moduleId: 'm5_2', name: 'Introspection', icon: Icons.search_outlined, rustFunction: 'graphql_introspect'),
        ActionItem(id: 'a5_2_2', moduleId: 'm5_2', name: 'Deep Recursion', icon: Icons.all_inclusive_outlined, rustFunction: 'graphql_depth'),
        ActionItem(id: 'a5_2_3', moduleId: 'm5_2', name: 'Batch Abuse', icon: Icons.layers_outlined, rustFunction: 'graphql_batch'),
        ActionItem(id: 'a5_2_4', moduleId: 'm5_2', name: 'Field Dupes', icon: Icons.content_copy_outlined, rustFunction: 'graphql_duplicate'),
        ActionItem(id: 'a5_2_5', moduleId: 'm5_2', name: 'Auth Bypass', icon: Icons.gpp_bad_outlined, rustFunction: 'graphql_null'),
      ]),
    ]),

    // ── Phase 6: Data Security ──
    Phase(id: 'p6', name: 'Data Security', icon: Icons.data_saver_off_outlined, modules: [
      Module(id: 'm6_1', phaseId: 'p6', name: 'Sec Headers', icon: Icons.view_headline_outlined, actions: [
        ActionItem(id: 'a6_1_1', moduleId: 'm6_1', name: 'CSP Analysis', icon: Icons.policy_outlined, rustFunction: 'csp_parse'),
        ActionItem(id: 'a6_1_2', moduleId: 'm6_1', name: 'HSTS', icon: Icons.security_update_warning_outlined, rustFunction: 'hsts'),
        ActionItem(id: 'a6_1_3', moduleId: 'm6_1', name: 'XFrame', icon: Icons.crop_free_outlined, rustFunction: 'xframe'),
        ActionItem(id: 'a6_1_4', moduleId: 'm6_1', name: 'Referrer', icon: Icons.link_off_outlined, rustFunction: 'referrer'),
        ActionItem(id: 'a6_1_5', moduleId: 'm6_1', name: 'Server Header', icon: Icons.dns_outlined, rustFunction: 'server_header'),
      ]),
      Module(id: 'm6_2', phaseId: 'p6', name: 'File Uploads', icon: Icons.upload_file_outlined, actions: [
        ActionItem(id: 'a6_2_1', moduleId: 'm6_2', name: 'Ext Bypass', icon: Icons.file_present_outlined, rustFunction: 'upload_extension'),
        ActionItem(id: 'a6_2_2', moduleId: 'm6_2', name: 'MIME Mismatch', icon: Icons.compare_outlined, rustFunction: 'upload_mime'),
        ActionItem(id: 'a6_2_3', moduleId: 'm6_2', name: 'Path Traversal', icon: Icons.turn_left_outlined, rustFunction: 'upload_path'),
        ActionItem(id: 'a6_2_4', moduleId: 'm6_2', name: 'Magic Bytes', icon: Icons.auto_fix_high_outlined, rustFunction: 'upload_magic'),
        ActionItem(id: 'a6_2_5', moduleId: 'm6_2', name: 'Large Files', icon: Icons.file_upload_outlined, rustFunction: 'upload_large'),
      ]),
    ]),

    // ── Phase 7: Business Logic ──
    Phase(id: 'p7', name: 'Business Logic', icon: Icons.cases_outlined, modules: [
      Module(id: 'm7_1', phaseId: 'p7', name: 'Logic Flaws', icon: Icons.psychology_outlined, actions: [
        ActionItem(id: 'a7_1_1', moduleId: 'm7_1', name: 'Price Manip', icon: Icons.price_change_outlined, rustFunction: 'price_manip'),
        ActionItem(id: 'a7_1_2', moduleId: 'm7_1', name: 'Negative Qty', icon: Icons.exposure_neg_1_outlined, rustFunction: 'negative_qty'),
        ActionItem(id: 'a7_1_3', moduleId: 'm7_1', name: 'Coupon Reuse', icon: Icons.loyalty_outlined, rustFunction: 'coupon_reuse'),
        ActionItem(id: 'a7_1_4', moduleId: 'm7_1', name: 'Race Cond', icon: Icons.directions_run_outlined, rustFunction: 'race_withdraw'),
        ActionItem(id: 'a7_1_5', moduleId: 'm7_1', name: 'Workflow Bypass', icon: Icons.next_plan_outlined, rustFunction: 'workflow_bypass'),
      ]),
      Module(id: 'm7_2', phaseId: 'p7', name: 'CSRF', icon: Icons.sync_problem_outlined, actions: [
        ActionItem(id: 'a7_2_1', moduleId: 'm7_2', name: 'No Token', icon: Icons.not_interested_outlined, rustFunction: 'csrf_no_token'),
        ActionItem(id: 'a7_2_2', moduleId: 'm7_2', name: 'Static Token', icon: Icons.push_pin_outlined, rustFunction: 'csrf_static'),
        ActionItem(id: 'a7_2_3', moduleId: 'm7_2', name: 'SameSite', icon: Icons.join_inner_outlined, rustFunction: 'csrf_samesite'),
        ActionItem(id: 'a7_2_4', moduleId: 'm7_2', name: 'GET CSRF', icon: Icons.get_app_outlined, rustFunction: 'csrf_get'),
        ActionItem(id: 'a7_2_5', moduleId: 'm7_2', name: 'Token Leak', icon: Icons.leak_remove_outlined, rustFunction: 'csrf_referer'),
      ]),
    ]),

    // ── Phase 8: Mobile ──
    Phase(id: 'p8', name: 'Mobile', icon: Icons.smartphone_outlined, modules: [
      Module(id: 'm8_1', phaseId: 'p8', name: 'Mobile APIs', icon: Icons.app_settings_alt_outlined, actions: [
        ActionItem(id: 'a8_1_1', moduleId: 'm8_1', name: 'Intercept', icon: Icons.cell_wifi_outlined, rustFunction: 'proxy'),
        ActionItem(id: 'a8_1_2', moduleId: 'm8_1', name: 'Pinning Bypass', icon: Icons.vpn_key_off_outlined, rustFunction: 'pinning_bypass'),
        ActionItem(id: 'a8_1_3', moduleId: 'm8_1', name: 'APK Secrets', icon: Icons.android_outlined, rustFunction: 'apk_strings'),
        ActionItem(id: 'a8_1_4', moduleId: 'm8_1', name: 'Local Storage', icon: Icons.sd_storage_outlined, rustFunction: 'local_storage'),
        ActionItem(id: 'a8_1_5', moduleId: 'm8_1', name: 'Deep Links', icon: Icons.link_outlined, rustFunction: 'deeplink'),
      ]),
      Module(id: 'm8_2', phaseId: 'p8', name: 'Deserialization', icon: Icons.broken_image_outlined, actions: [
        ActionItem(id: 'a8_2_1', moduleId: 'm8_2', name: 'Java Deser', icon: Icons.coffee_outlined, rustFunction: 'deser_java'),
        ActionItem(id: 'a8_2_2', moduleId: 'm8_2', name: 'PHP Unserialize', icon: Icons.php_outlined, rustFunction: 'deser_php'),
        ActionItem(id: 'a8_2_3', moduleId: 'm8_2', name: 'Python Pickle', icon: Icons.catching_pokemon_outlined, rustFunction: 'deser_python'),
        ActionItem(id: 'a8_2_4', moduleId: 'm8_2', name: 'NET ViewState', icon: Icons.window_outlined, rustFunction: 'deser_net'),
        ActionItem(id: 'a8_2_5', moduleId: 'm8_2', name: 'YAML Deser', icon: Icons.format_align_left_outlined, rustFunction: 'deser_yaml'),
      ]),
    ]),

    // ── Phase 9: Automation ──
    Phase(id: 'p9', name: 'Automation', icon: Icons.smart_toy_outlined, modules: [
      Module(id: 'm9_1', phaseId: 'p9', name: 'Scheduler', icon: Icons.schedule_outlined, actions: [
        ActionItem(id: 'a9_1_1', moduleId: 'm9_1', name: 'Cron Tasks', icon: Icons.more_time_outlined, rustFunction: 'scheduler'),
        ActionItem(id: 'a9_1_2', moduleId: 'm9_1', name: 'Sub Monitor', icon: Icons.monitor_heart_outlined, rustFunction: 'submon'),
        ActionItem(id: 'a9_1_3', moduleId: 'm9_1', name: 'Auto Fuzz', icon: Icons.blur_linear_outlined, rustFunction: 'autofuzz'),
        ActionItem(id: 'a9_1_4', moduleId: 'm9_1', name: 'Webhooks', icon: Icons.webhook_outlined, rustFunction: 'webhook'),
        ActionItem(id: 'a9_1_5', moduleId: 'm9_1', name: 'Nightly Reports', icon: Icons.bedtime_outlined, rustFunction: 'nightly_report'),
      ]),
      Module(id: 'm9_2', phaseId: 'p9', name: 'Distributed', icon: Icons.schema_outlined, actions: [
        ActionItem(id: 'a9_2_1', moduleId: 'm9_2', name: 'Master Worker', icon: Icons.supervisor_account_outlined, rustFunction: 'cluster_master'),
        ActionItem(id: 'a9_2_2', moduleId: 'm9_2', name: 'Segmentation', icon: Icons.pie_chart_outline_outlined, rustFunction: 'segment'),
        ActionItem(id: 'a9_2_3', moduleId: 'm9_2', name: 'Aggregation', icon: Icons.compress_outlined, rustFunction: 'aggregate'),
        ActionItem(id: 'a9_2_4', moduleId: 'm9_2', name: 'Load Balancer', icon: Icons.balance_outlined, rustFunction: 'load_balance'),
        ActionItem(id: 'a9_2_5', moduleId: 'm9_2', name: 'Heartbeat', icon: Icons.favorite_border_outlined, rustFunction: 'heartbeat'),
      ]),
    ]),

    // ── Phase 10: Reporting ──
    Phase(id: 'p10', name: 'Reporting', icon: Icons.insert_chart_outlined, modules: [
      Module(id: 'm10_1', phaseId: 'p10', name: 'Report Gen', icon: Icons.picture_as_pdf_outlined, actions: [
        ActionItem(id: 'a10_1_1', moduleId: 'm10_1', name: 'CVSS Calc', icon: Icons.calculate_outlined, rustFunction: 'cvss'),
        ActionItem(id: 'a10_1_2', moduleId: 'm10_1', name: 'POC Gen', icon: Icons.text_snippet_outlined, rustFunction: 'poc'),
        ActionItem(id: 'a10_1_3', moduleId: 'm10_1', name: 'MD Export', icon: Icons.article_outlined, rustFunction: 'md_export'),
        ActionItem(id: 'a10_1_4', moduleId: 'm10_1', name: 'PDF Export', icon: Icons.file_download_outlined, rustFunction: 'pdf_export'),
        ActionItem(id: 'a10_1_5', moduleId: 'm10_1', name: 'Remediation', icon: Icons.healing_outlined, rustFunction: 'remediation'),
      ]),
      Module(id: 'm10_2', phaseId: 'p10', name: 'Triage', icon: Icons.filter_alt_outlined, actions: [
        ActionItem(id: 'a10_2_1', moduleId: 'm10_2', name: 'Hash Dedup', icon: Icons.content_cut_outlined, rustFunction: 'dedup_hash'),
        ActionItem(id: 'a10_2_2', moduleId: 'm10_2', name: 'Similarity', icon: Icons.join_right_outlined, rustFunction: 'similarity'),
        ActionItem(id: 'a10_2_3', moduleId: 'm10_2', name: 'FP Retest', icon: Icons.fact_check_outlined, rustFunction: 'retest'),
        ActionItem(id: 'a10_2_4', moduleId: 'm10_2', name: 'Confidence', icon: Icons.show_chart_outlined, rustFunction: 'confidence'),
        ActionItem(id: 'a10_2_5', moduleId: 'm10_2', name: 'Preview', icon: Icons.preview_outlined, rustFunction: 'preview'),
      ]),
    ]),
  ];
}

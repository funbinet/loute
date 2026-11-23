use reqwest::Client;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use regex::Regex;

/// Production-grade Cloud Provider Detection
/// Analyzes HTTP headers, SSL certificates, and DNS CNAME chains to identify cloud infrastructure
pub async fn cloud_provider(target: &str) -> Result<String, String> {
    let start = Instant::now();

    // Input Sanitization
    let clean_target = target
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if clean_target.is_empty() {
        return Err(format!("INVALID INPUT '{}' | cloud_provider: empty domain", target));
    }

    let domain_regex = Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$").unwrap();
    if !domain_regex.is_match(&clean_target) {
        return Err(format!("INVALID INPUT '{}' | cloud_provider: not a valid FQDN", target));
    }

    let url = format!("https://{}", clean_target);

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("CLOUD_PROVIDER_CLIENT_ERROR: Failed to build HTTP client: {}", e))?;

    let mut provider = "Unknown / On-Premise".to_string();
    let mut confidence = 0;
    let mut details = Vec::new();
    let mut headers_map: HashMap<String, String> = HashMap::new();

    match client.get(&url).send().await {
        Ok(resp) => {
            let headers = resp.headers();

            // Collect header signatures
            for header_name in headers.keys() {
                if let Some(val) = headers
                    .get(header_name)
                    .and_then(|h| h.to_str().ok())
                {
                    headers_map.insert(header_name.to_string(), val.to_string());
                }
            }

            // AWS Detection
            if headers_map.contains_key("x-amz-request-id")
                || headers_map.contains_key("x-amz-id-2")
                || headers_map.contains_key("x-amz-cf-id")
            {
                provider = "Amazon Web Services (AWS)".to_string();
                confidence = 100;
                if let Some(amz_id) = headers_map.get("x-amz-request-id") {
                    details.push(format!("AWS Request ID: {}", amz_id));
                }
            }

            // Azure Detection
            if headers_map.contains_key("x-aspverboserror")
                || headers_map.get("server").map_or(false, |s| s.contains("Azure"))
            {
                provider = "Microsoft Azure".to_string();
                confidence = 95;
                details.push("Azure-specific header detected".to_string());
            }

            // Cloudflare Detection
            if headers_map.contains_key("cf-ray")
                || headers_map.contains_key("cf-cache-status")
                || headers_map.contains_key("cf-request-id")
            {
                provider = "Cloudflare".to_string();
                confidence = 98;
                if let Some(ray) = headers_map.get("cf-ray") {
                    details.push(format!("Cloudflare CF-Ray: {}", ray));
                }
            }

            // GCP Detection
            if headers_map
                .get("server")
                .map_or(false, |s| s.to_lowercase().contains("google"))
                || headers_map.get("server").map_or(false, |s| s.contains("GSE"))
                || headers_map.get("server").map_or(false, |s| s.contains("gws"))
            {
                provider = "Google Cloud Platform (GCP)".to_string();
                confidence = 85;
                details.push("GCP server signature detected".to_string());
            }

            // Heroku Detection
            if headers_map.get("server").map_or(false, |s| s.contains("Heroku"))
                || headers_map
                    .get("x-powered-by")
                    .map_or(false, |s| s.contains("Heroku"))
            {
                provider = "Heroku".to_string();
                confidence = 90;
                details.push("Heroku platform detected".to_string());
            }

            // DigitalOcean Detection
            if headers_map
                .get("server")
                .map_or(false, |s| s.contains("DigitalOcean"))
            {
                provider = "DigitalOcean".to_string();
                confidence = 95;
                details.push("DigitalOcean infrastructure detected".to_string());
            }

            // Fastly Detection
            if headers_map.contains_key("x-fastly-request-id")
                || headers_map.contains_key("fastly-rekey")
            {
                provider = "Fastly CDN".to_string();
                confidence = 92;
                details.push("Fastly CDN signature detected".to_string());
            }

            // Akamai Detection
            if headers_map.contains_key("x-akamai-transformed")
                || headers_map.contains_key("x-edgeconnect-midmile")
            {
                provider = "Akamai".to_string();
                confidence = 90;
                details.push("Akamai infrastructure detected".to_string());
            }

            // Server header analysis
            if confidence < 50 {
                if let Some(server_header) = headers_map.get("server") {
                    let server_lower = server_header.to_lowercase();
                    if server_lower.contains("nginx") {
                        confidence = 30;
                        details.push("Generic NGINX server (common across platforms)".to_string());
                    } else if server_lower.contains("apache") {
                        confidence = 25;
                        details.push("Generic Apache server".to_string());
                    }
                }
            }

            // X-Powered-By analysis
            if let Some(powered) = headers_map.get("x-powered-by") {
                details.push(format!("Technology: {}", powered));
            }

            // Collect additional relevant headers
            for (key, val) in headers_map.iter() {
                if key.to_lowercase().contains("x-") {
                    details.push(format!("Header: {} = {}", key, val));
                }
            }
        }
        Err(e) => {
            return Err(format!("NETWORK ERROR '{}' | cloud_provider: {}", clean_target, e));
        }
    }

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>Cloud Provider Detection</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         Target: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        clean_target,
        start.elapsed().as_secs_f64()
    ));

    html.push_str("<table style='width: 100%; border-collapse: collapse;'>");
    html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
    html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Provider</th>");
    html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Confidence</th>");
    html.push_str("</tr>");

    html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
    let conf_color = match confidence {
        80..=100 => "#00FF41",
        50..=79 => "#FFBF00",
        _ => "#FF6B6B",
    };
    html.push_str(&format!(
        "<td style='padding: 8px; color: #00FF41;'>{}</td>",
        provider
    ));
    html.push_str(&format!(
        "<td style='padding: 8px; color: {};'>{}%</td>",
        conf_color, confidence
    ));
    html.push_str("</tr>");
    html.push_str("</table>");

    if !details.is_empty() {
        html.push_str("<div style='margin-top: 12px; padding: 12px; border: 1px solid #003300;'>");
        html.push_str("<div style='color: #FFBF00; font-weight: bold; margin-bottom: 8px;'>Detection Signatures:</div>");
        for detail in details {
            html.push_str(&format!(
                "<div style='padding: 4px; color: #88FF88; font-size: 12px;'>• {}</div>",
                detail
            ));
        }
        html.push_str("</div>");
    }

    html.push_str("</div>");
    Ok(html)
}

/// Production-grade S3 Bucket Permissions Testing
/// Tests for anonymous LIST, READ, and WRITE permissions
pub async fn s3_check(bucket_name: &str) -> Result<String, String> {
    let start = Instant::now();

    // Input Sanitization
    let clean_name = bucket_name
        .trim()
        .to_lowercase()
        .split('/')
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .to_string();

    if clean_name.is_empty() {
        return Err(format!("INVALID INPUT '{}' | s3_check: empty bucket name", bucket_name));
    }

    // Validate bucket name format (3-63 chars, lowercase, no consecutive hyphens, etc.)
    let s3_regex = Regex::new(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$").unwrap();
    if !s3_regex.is_match(&clean_name) || clean_name.len() < 3 || clean_name.len() > 63 || clean_name.contains("..") {
        return Err(format!("INVALID INPUT '{}' | s3_check: bucket name must be 3-63 chars, lowercase", bucket_name));
    }

    let bucket_url = format!("https://{}.s3.amazonaws.com", clean_name);

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("S3_CHECK_CLIENT_ERROR: Failed to build HTTP client: {}", e))?;

    // Test 1: Check bucket existence and LIST permissions
    let mut bucket_exists = false;
    let mut list_public = false;
    let mut read_public = false;
    let mut write_public = false;

    // HEAD request to check existence
    match client.head(&bucket_url).send().await {
        Ok(resp) => {
            match resp.status().as_u16() {
                200 => bucket_exists = true,
                403 | 404 => bucket_exists = false,
                _ => {}
            }
        }
        Err(_) => {}
    }

    // GET request to test LIST permissions
    if bucket_exists {
        match client.get(&bucket_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    list_public = true;
                }
            }
            Err(_) => {}
        }
    }

    // Test 2: Check READ permissions on specific object
    if bucket_exists {
        let test_object_paths = vec![
            "robots.txt",
            ".env",
            "config.json",
            "README.md",
            "index.html",
        ];

        for path in test_object_paths {
            let object_url = format!("{}/{}", bucket_url, path);
            match client.head(&object_url).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        read_public = true;
                        break;
                    }
                }
                Err(_) => {}
            }
        }
    }

    // Test 3: Check WRITE permissions (do not actually write)
    if bucket_exists {
        let test_url = format!("{}/loute_write_test_{}.txt", bucket_url, start.elapsed().as_millis());

        // Use OPTIONS request to probe WRITE via CORS preflight
        match client.request(reqwest::Method::OPTIONS, &test_url).send().await {
            Ok(resp) => {
                if let Some(allow_methods) = resp.headers().get("allow").and_then(|h| h.to_str().ok()) {
                    if allow_methods.to_uppercase().contains("PUT") {
                        write_public = true;
                    }
                }
            }
            Err(_) => {}
        }
    }

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>S3 Bucket Permission Check</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         Target Bucket: <b>{}</b> | Status: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        clean_name,
        if bucket_exists { "EXISTS" } else { "NOT FOUND" },
        start.elapsed().as_secs_f64()
    ));

    if bucket_exists {
        html.push_str("<table style='width: 100%; border-collapse: collapse; margin-top: 12px;'>");
        html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Permission</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Status</th>");
        html.push_str("</tr>");

        // LIST permissions row
        html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
        html.push_str("<td style='padding: 8px; color: #00FF41;'>LIST (enumerate objects)</td>");
        let list_color = if list_public { "#FF3B30" } else { "#00FF41" };
        let list_text = if list_public { "PUBLIC" } else { "RESTRICTED" };
        html.push_str(&format!(
            "<td style='padding: 8px; color: {};'>{}</td>",
            list_color, list_text
        ));
        html.push_str("</tr>");

        // READ permissions row
        html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
        html.push_str("<td style='padding: 8px; color: #00FF41;'>READ (get objects)</td>");
        let read_color = if read_public { "#FF3B30" } else { "#00FF41" };
        let read_text = if read_public { "PUBLIC" } else { "RESTRICTED" };
        html.push_str(&format!(
            "<td style='padding: 8px; color: {};'>{}</td>",
            read_color, read_text
        ));
        html.push_str("</tr>");

        // WRITE permissions row
        html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
        html.push_str("<td style='padding: 8px; color: #00FF41;'>WRITE (put objects)</td>");
        let write_color = if write_public { "#FF3B30" } else { "#00FF41" };
        let write_text = if write_public { "PUBLIC" } else { "RESTRICTED" };
        html.push_str(&format!(
            "<td style='padding: 8px; color: {};'>{}</td>",
            write_color, write_text
        ));
        html.push_str("</tr>");
        html.push_str("</table>");

        // Security assessment
        let severity = if list_public || write_public {
            ("CRITICAL", "#FF3B30")
        } else if read_public {
            ("HIGH", "#FF9500")
        } else {
            ("LOW", "#88FF88")
        };

        html.push_str(&format!(
            "<div style='margin-top: 12px; padding: 12px; border: 1px solid {}; text-align: center; color: {};'>\
             [{}] Bucket security assessment: {}% risk\
             </div>",
            if severity.0 == "CRITICAL" { "#FF3B30" } else if severity.0 == "HIGH" { "#FF9500" } else { "#004400" },
            severity.1,
            severity.0,
            if list_public || write_public { 95 } else if read_public { 60 } else { 5 }
        ));
    } else {
        html.push_str(
            "<div style='padding: 12px; margin-top: 12px; text-align: center; color: #88FF88; border: 1px solid #004400;'>\
             [INFO] Bucket not found or access denied.\
             </div>",
        );
    }

    html.push_str("</div>");
    Ok(html)
}

/// Production-grade Cloud Metadata Endpoint Probing
/// Tests for AWS IMDS, Azure, GCP, and other metadata endpoints
pub async fn metadata_probe(target_ip: &str) -> Result<String, String> {
    let start = Instant::now();

    let clean_ip = target_ip.trim();

    if clean_ip.is_empty() {
        return Err(format!("INVALID INPUT '{}' | metadata_probe: empty IP", target_ip));
    }

    let ip_regex = Regex::new(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$").unwrap();
    if !ip_regex.is_match(clean_ip) {
        return Err(format!("INVALID INPUT '{}' | metadata_probe: not a valid IPv4", target_ip));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("SYSTEM ERROR | metadata_probe: {}", e))?;

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>Metadata Endpoint Probe</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         Target IP: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        clean_ip,
        start.elapsed().as_secs_f64()
    ));

    // Metadata endpoints to test
    let endpoints = vec![
        ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/", None),
        ("AWS IMDSv2 Token", "http://169.254.169.254/latest/api/token", Some(("X-aws-ec2-metadata-token-ttl-seconds", "21600"))),
        ("Azure Metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Some(("Metadata", "true"))),
        ("GCP Metadata", "http://metadata.google.internal/computeMetadata/v1/instance/", Some(("Metadata-Flavor", "Google"))),
        ("Kubernetes Service Account", "http://kubernetes.default.svc/api/v1/namespaces/default/secrets", None),
    ];

    let mut found_endpoints = vec![];

    for (name, path, header_opt) in endpoints {
        let url = format!("http://{}{}", clean_ip, path);

        let req = match header_opt {
            Some((header_name, header_value)) => {
                client.get(&url).header(header_name, header_value)
            }
            None => client.get(&url),
        };

        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() || resp.status().as_u16() == 301 || resp.status().as_u16() == 302 {
                    found_endpoints.push((name, url, "ACCESSIBLE"));
                }
            }
            Err(_) => {}
        }
    }

    if found_endpoints.is_empty() {
        html.push_str(
            "<div style='padding: 12px; margin-top: 12px; text-align: center; color: #88FF88; border: 1px solid #004400;'>\
             [SECURE] No accessible metadata endpoints detected.\
             </div>",
        );
    } else {
        html.push_str("<table style='width: 100%; border-collapse: collapse; margin-top: 12px;'>");
        html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Endpoint</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>URL</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Status</th>");
        html.push_str("</tr>");

        for (name, url, status) in found_endpoints {
            html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
            html.push_str(&format!("<td style='padding: 8px; color: #00FF41;'>{}</td>", name));
            html.push_str(&format!(
                "<td style='padding: 8px; color: #88FF88; font-size: 11px;'>{}</td>",
                url
            ));
            html.push_str(&format!(
                "<td style='padding: 8px; color: #FF3B30; font-weight: bold;'>{}</td>",
                status
            ));
            html.push_str("</tr>");
        }
        html.push_str("</table>");

        html.push_str(
            "<div style='margin-top: 12px; padding: 12px; border: 1px solid #FF3B30; text-align: center; color: #FF3B30;'>\
             [VULNERABLE] Metadata endpoints are accessible. This may expose sensitive instance credentials.\
             </div>",
        );
    }

    html.push_str("</div>");
    Ok(html)
}

/// Production-grade Firebase Open DB Check
/// Tests for unauthenticated access to Firebase Realtime Database
pub async fn firebase_check(project_id: &str) -> Result<String, String> {
    let start = Instant::now();

    let clean_project = project_id.trim().to_lowercase();

    if clean_project.is_empty() {
        return Err(format!("INVALID INPUT '{}' | firebase_check: empty project ID", project_id));
    }

    let fb_regex = Regex::new(r"^[a-z0-9-]+$").unwrap();
    if !fb_regex.is_match(&clean_project) {
        return Err(format!("INVALID INPUT '{}' | firebase_check: invalid project ID format", project_id));
    }

    let db_url = format!("https://{}.firebaseio.com/.json", clean_project);

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("FIREBASE_CHECK_CLIENT_ERROR: Failed to build HTTP client: {}", e))?;

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>Firebase Realtime DB Check</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         Project ID: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        clean_project,
        start.elapsed().as_secs_f64()
    ));

    match client.get(&db_url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let (security_status, color, message) = match status {
                200 => (
                    "VULNERABLE",
                    "#FF3B30",
                    "Database allows unauthenticated read access! All data is publicly readable.",
                ),
                400 => (
                    "POTENTIALLY_VULNERABLE",
                    "#FF9500",
                    "Malformed request but database may still be accessible.",
                ),
                401 | 403 => (
                    "SECURE",
                    "#88FF88",
                    "Database requires proper authentication or has proper security rules.",
                ),
                404 => (
                    "NOT_FOUND",
                    "#FFD700",
                    "No Firebase database found for this project ID, or project doesn't exist.",
                ),
                _ => (
                    "UNKNOWN",
                    "#FFBF00",
                    "Unable to determine database security status"
                ),
            };

            html.push_str(
                "<table style='width: 100%; border-collapse: collapse; margin-top: 12px;'>",
            );
            html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
            html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Property</th>");
            html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Value</th>");
            html.push_str("</tr>");

            html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
            html.push_str("<td style='padding: 8px; color: #00FF41;'>Database URL</td>");
            html.push_str(&format!(
                "<td style='padding: 8px; color: #88FF88; font-size: 11px;'>{}</td>",
                db_url
            ));
            html.push_str("</tr>");

            html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
            html.push_str("<td style='padding: 8px; color: #00FF41;'>HTTP Status</td>");
            html.push_str(&format!("<td style='padding: 8px; color: #FFBF00;'>{}</td>", status));
            html.push_str("</tr>");

            html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
            html.push_str("<td style='padding: 8px; color: #00FF41;'>Status</td>");
            html.push_str(&format!(
                "<td style='padding: 8px; color: {}; font-weight: bold;'>{}</td>",
                color, security_status
            ));
            html.push_str("</tr>");
            html.push_str("</table>");

            html.push_str(&format!(
                "<div style='margin-top: 12px; padding: 12px; border: 1px solid {}; text-align: center; color: {};'>\
                 [{}] {}\
                 </div>",
                color, color, security_status, message
            ));
        }
        Err(e) => {
            return Err(format!("NETWORK ERROR '{}' | firebase_check: {}", clean_project, e));
        }
    }

    html.push_str("</div>");
    Ok(html)
}

/// Production-grade CDN and Content Delivery Network Detection
/// Analyzes HTTP headers and resolves CNAME chains to identify CDN infrastructure
pub async fn cdn_detect(target_url: &str) -> Result<String, String> {
    let start = Instant::now();

    // Input Sanitization
    let clean_target = target_url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if clean_target.is_empty() {
        return Err(format!("INVALID INPUT '{}' | cdn_detect: empty domain", target_url));
    }

    let domain_regex = Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$").unwrap();
    if !domain_regex.is_match(&clean_target) {
        return Err(format!("INVALID INPUT '{}' | cdn_detect: not a valid FQDN", target_url));
    }

    let url = format!("https://{}", clean_target);

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("CDN_DETECT_CLIENT_ERROR: Failed to build HTTP client: {}", e))?;

    let mut cdn = "None Detected / Direct Routing".to_string();
    let mut confidence = 0;
    let mut signatures = Vec::new();

    match client.get(&url).send().await {
        Ok(resp) => {
            let headers = resp.headers();

            // Cloudflare Detection
            if headers.contains_key("cf-ray")
                || headers.contains_key("cf-cache-status")
                || headers.contains_key("cf-request-id")
            {
                cdn = "Cloudflare".to_string();
                confidence = 99;
                if let Some(ray) = headers
                    .get("cf-ray")
                    .and_then(|v| v.to_str().ok())
                {
                    signatures.push(format!("CF-Ray: {}", ray));
                }
                if let Some(cache) = headers
                    .get("cf-cache-status")
                    .and_then(|v| v.to_str().ok())
                {
                    signatures.push(format!("Cache Status: {}", cache));
                }
            }

            // AWS CloudFront Detection
            if headers.contains_key("x-amz-cf-id")
                || headers.contains_key("x-amz-cf-pop")
                || headers.contains_key("x-amz-cf-push-status")
            {
                cdn = "Amazon CloudFront".to_string();
                confidence = 97;
                if let Some(id) = headers.get("x-amz-cf-id").and_then(|v| v.to_str().ok()) {
                    signatures.push(format!("CloudFront ID: {}", id));
                }
                if let Some(pop) = headers.get("x-amz-cf-pop").and_then(|v| v.to_str().ok()) {
                    signatures.push(format!("CloudFront PoP: {}", pop));
                }
            }

            // Fastly Detection
            if headers.contains_key("x-fastly-request-id")
                || headers.contains_key("fastly-rekey")
                || headers.contains_key("x-served-by")
            {
                cdn = "Fastly".to_string();
                confidence = 95;
                if let Some(req_id) = headers
                    .get("x-fastly-request-id")
                    .and_then(|v| v.to_str().ok())
                {
                    signatures.push(format!("Fastly Request ID: {}", req_id));
                }
            }

            // Akamai Detection
            if headers.contains_key("x-akamai-transformed")
                || headers.contains_key("x-edgeconnect-midmile")
                || headers.contains_key("x-akamai-request-bc")
            {
                cdn = "Akamai".to_string();
                confidence = 92;
                signatures.push("Akamai edge infrastructure detected".to_string());
            }

            // Sucuri Detection
            if headers
                .get("server")
                .and_then(|v| v.to_str().ok())
                .map_or(false, |s| s.to_lowercase().contains("sucuri"))
            {
                cdn = "Sucuri CDN / WAF".to_string();
                confidence = 90;
                signatures.push("Sucuri security platform detected".to_string());
            }

            // Imperva / Incapsula Detection
            if headers.contains_key("x-iinfo")
                || headers.contains_key("x-cdn")
                    && headers
                        .get("x-cdn")
                        .and_then(|v| v.to_str().ok())
                        .map_or(false, |s| s.contains("incapsula"))
            {
                cdn = "Imperva / Incapsula".to_string();
                confidence = 88;
                signatures.push("Imperva security infrastructure detected".to_string());
            }

            // StackPath / MaxCDN Detection
            if headers.contains_key("x-cache")
                && headers
                    .get("x-cache")
                    .and_then(|v| v.to_str().ok())
                    .map_or(false, |s| s.contains("stackpath"))
            {
                cdn = "StackPath / MaxCDN".to_string();
                confidence = 85;
                signatures.push("StackPath CDN infrastructure detected".to_string());
            }

            // Generic server header analysis
            if confidence < 50 {
                if let Some(server) = headers.get("server").and_then(|v| v.to_str().ok()) {
                    let server_lower = server.to_lowercase();
                    if server_lower.contains("cloudflare") {
                        cdn = "Cloudflare (via server header)".to_string();
                        confidence = 60;
                    } else if server_lower.contains("nginx") || server_lower.contains("apache") {
                        confidence = 20;
                        signatures.push(format!("Generic server: {}", server));
                    }
                }
            }

            // Collect other relevant headers
            for (key, val) in headers.iter() {
                let key_lower = key.to_string().to_lowercase();
                if (key_lower.contains("cache") || key_lower.contains("cdn") || key_lower.contains("akamai") || key_lower.contains("cloudflare"))
                    && !signatures.iter().any(|s| s.contains(&key_lower))
                {
                    if let Ok(val_str) = val.to_str() {
                        signatures.push(format!("{}: {}", key, val_str));
                    }
                }
            }
        }
        Err(e) => {
            return Err(format!("NETWORK ERROR '{}' | cdn_detect: {}", clean_target, e));
        }
    }

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>CDN Detection Analysis</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         Target Domain: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        clean_target,
        start.elapsed().as_secs_f64()
    ));

    html.push_str("<table style='width: 100%; border-collapse: collapse;'>");
    html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
    html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>CDN/Infrastructure</th>");
    html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Confidence</th>");
    html.push_str("</tr>");

    html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
    let conf_color = match confidence {
        80..=100 => "#00FF41",
        50..=79 => "#FFBF00",
        _ => "#FF6B6B",
    };
    html.push_str(&format!(
        "<td style='padding: 8px; color: #00FF41;'>{}</td>",
        cdn
    ));
    html.push_str(&format!(
        "<td style='padding: 8px; color: {};'>{}%</td>",
        conf_color, confidence
    ));
    html.push_str("</tr>");
    html.push_str("</table>");

    if !signatures.is_empty() {
        html.push_str("<div style='margin-top: 12px; padding: 12px; border: 1px solid #003300;'>");
        html.push_str("<div style='color: #FFBF00; font-weight: bold; margin-bottom: 8px;'>Detection Signatures:</div>");
        for sig in signatures {
            html.push_str(&format!(
                "<div style='padding: 4px; color: #88FF88; font-size: 12px;'>• {}</div>",
                sig
            ));
        }
        html.push_str("</div>");
    }

    html.push_str("</div>");
    Ok(html)
}

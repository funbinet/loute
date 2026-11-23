use std::collections::HashMap;
use std::time::Instant;

/// Production-grade Host Network Services Audit
/// Detects and reports listening network services with service identification
pub async fn network_services_audit() -> Result<String, String> {
    let start = Instant::now();
    let os = std::env::consts::OS;

    let mut html = String::new();
    html.push_str("<div style='font-family: monospace; color: #00FF41; background-color: #000000; padding: 16px; border: 1px solid #00FF41;'>");
    html.push_str("<h2 style='color: #FFBF00; border-bottom: 1px solid #00FF41; margin-top: 0; padding-bottom: 8px;'>Host Network Services Audit</h2>");

    html.push_str(&format!(
        "<div style='margin-bottom: 12px; font-size: 12px; color: #88FF88;'>\
         OS: <b>{}</b> | Duration: <b>{:.2}s</b>\
         </div>",
        os.to_uppercase(),
        start.elapsed().as_secs_f64()
    ));

    // Define common service ports mapping
    let service_map = create_service_map();

    let (services, error_option) = match os {
        "linux" => query_linux_services().await,
        "macos" => query_macos_services().await,
        "windows" => query_windows_services().await,
        "android" => query_android_services().await,
        _ => (vec![], Some("NETWORK_AUDIT_UNSUPPORTED_OS: Unsupported operating system".to_string())),
    };

    if let Some(err) = error_option {
        html.push_str(&format!(
            "<div style='padding: 12px; margin-top: 12px; border: 1px solid #FF3B30; color: #FF3B30;'>\
             <b>Audit Warning:</b> {}\
             </div>",
            err
        ));
    }

    if services.is_empty() {
        html.push_str(
            "<div style='padding: 12px; text-align: center; color: #88FF88; border: 1px solid #004400; margin-top: 12px;'>\
             [INFO] No listening services detected or commands unavailable.\
             </div>",
        );
    } else {
        html.push_str("<table style='width: 100%; border-collapse: collapse; margin-top: 12px;'>");
        html.push_str("<tr style='border-bottom: 2px solid #00FF41;'>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Protocol</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Local Address</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Port</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>Service</th>");
        html.push_str("<th style='padding: 8px; color: #FFBF00; text-align: left;'>State</th>");
        html.push_str("</tr>");

        for service in &services {
            // Extract port from local address
            let port = extract_port(&service.local_addr).unwrap_or_default();
            let service_name = service_map
                .get(&port)
                .copied()
                .unwrap_or(&service.service_name);

            let state_color = match service.state.as_str() {
                "LISTEN" | "LISTENING" => "#00FF41",
                "ESTABLISHED" => "#FFBF00",
                "TIME_WAIT" | "CLOSE_WAIT" => "#FF9500",
                _ => "#88FF88",
            };

            html.push_str("<tr style='border-bottom: 1px solid #1a3a1a;'>");
            html.push_str(&format!(
                "<td style='padding: 8px; color: #88FF88;'>{}</td>",
                service.protocol
            ));
            html.push_str(&format!(
                "<td style='padding: 8px; color: #00FF41;'>{}</td>",
                service.local_addr
            ));
            html.push_str(&format!(
                "<td style='padding: 8px; color: #FFBF00;'>{}</td>",
                port
            ));
            html.push_str(&format!(
                "<td style='padding: 8px; color: #FFBF00; font-weight: bold;'>{}</td>",
                service_name
            ));
            html.push_str(&format!(
                "<td style='padding: 8px; color: {};'>{}</td>",
                state_color, service.state
            ));
            html.push_str("</tr>");
        }
        html.push_str("</table>");

        html.push_str(&format!(
            "<div style='margin-top: 12px; padding: 12px; text-align: center; color: #88FF88; border: 1px solid #004400;'>\
             [INFO] Discovered {} active network services\
             </div>",
            services.len()
        ));
    }

    html.push_str("</div>");
    Ok(html)
}

/// Data structure for network service information
#[derive(Clone, Debug)]
struct NetworkService {
    protocol: String,
    local_addr: String,
    remote_addr: String,
    state: String,
    service_name: String,
}

/// Query running services on Linux (ss/netstat)
async fn query_linux_services() -> (Vec<NetworkService>, Option<String>) {
    let mut services = Vec::new();

    // Try ss first (more reliable on modern Linux)
    if let Ok(output) = tokio::process::Command::new("ss")
        .args(&["-tln", "-n"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_linux_ss_output(&stdout, &mut services);
            return (services, None);
        }
    }

    // Fallback to netstat
    if let Ok(output) = tokio::process::Command::new("netstat")
        .args(&["-tln", "-n"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_linux_netstat_output(&stdout, &mut services);
            return (services, None);
        }
    }

    // Additional fallback to lsof if available
    if let Ok(output) = tokio::process::Command::new("lsof")
        .args(&["-i", "-P", "-n"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_lsof_output(&stdout, &mut services);
            return (services, None);
        }
    }

    (
        services,
        Some("NETWORK_AUDIT_COMMAND_FAILED: Unable to execute ss, netstat, or lsof commands".to_string()),
    )
}

/// Query running services on macOS
async fn query_macos_services() -> (Vec<NetworkService>, Option<String>) {
    let mut services = Vec::new();

    // lsof is more reliable on macOS
    if let Ok(output) = tokio::process::Command::new("lsof")
        .args(&["-i", "-P", "-n"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_lsof_output(&stdout, &mut services);
            if !services.is_empty() {
                return (services, None);
            }
        }
    }

    // Fallback to netstat
    if let Ok(output) = tokio::process::Command::new("netstat")
        .args(&["-an", "-f", "inet"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_macos_netstat_output(&stdout, &mut services);
            return (services, None);
        }
    }

    (
        services,
        Some("NETWORK_AUDIT_COMMAND_FAILED: Unable to execute lsof or netstat on macOS".to_string()),
    )
}

/// Query running services on Windows
async fn query_windows_services() -> (Vec<NetworkService>, Option<String>) {
    let mut services = Vec::new();

    if let Ok(output) = tokio::process::Command::new("netstat")
        .args(&["-ano", "-p", "tcp"])
        .output()
        .await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_windows_netstat_output(&stdout, &mut services);
            if !services.is_empty() {
                return (services, None);
            }
        }
    }

    (
        services,
        Some("NETWORK_AUDIT_COMMAND_FAILED: Unable to execute netstat on Windows".to_string()),
    )
}

/// Query running services on Android via localhost limited port scan
async fn query_android_services() -> (Vec<NetworkService>, Option<String>) {
    let mut services = Vec::new();
    let ports = [22, 53, 80, 443, 3306, 5432, 8080, 8443, 27017, 6379, 5984];
    
    for port in ports.iter() {
        if let Ok(_) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            services.push(NetworkService {
                protocol: "TCP".to_string(),
                local_addr: format!("127.0.0.1:{}", port),
                remote_addr: "-".to_string(),
                state: "LISTEN".to_string(),
                service_name: "Unknown".to_string(),
            });
        }
    }
    
    if services.is_empty() {
        (services, Some("NETWORK_AUDIT_ANDROID_RESTRICTED: ss/netstat unavailable without root. Limited localhost port scan found no services.".to_string()))
    } else {
        (services, Some("NETWORK_AUDIT_ANDROID_RESTRICTED: ss/netstat unavailable without root. Results are from a limited localhost port scan.".to_string()))
    }
}

/// Parse Linux ss output (ss -tln -n)
fn parse_linux_ss_output(output: &str, services: &mut Vec<NetworkService>) {
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        // ss output format: State Recv-Q Send-Q Local-Address Foreign-Address
        let state = parts[0];
        if !state.eq_ignore_ascii_case("listen") {
            continue;
        }

        let local_addr = parts[3];
        let foreign_addr = parts.get(4).copied().unwrap_or("*:*");

        services.push(NetworkService {
            protocol: "TCP".to_string(),
            local_addr: local_addr.to_string(),
            remote_addr: foreign_addr.to_string(),
            state: state.to_string(),
            service_name: "Unknown".to_string(),
        });
    }
}

/// Parse Linux netstat output
fn parse_linux_netstat_output(output: &str, services: &mut Vec<NetworkService>) {
    for line in output.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let protocol = parts[0];
        let local_addr = parts[3];
        let remote_addr = parts[4];
        let state = parts[5];

        if state.eq_ignore_ascii_case("listen") || state.eq_ignore_ascii_case("established") {
            services.push(NetworkService {
                protocol: protocol.to_uppercase(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: state.to_string(),
                service_name: "Unknown".to_string(),
            });
        }
    }
}

/// Parse macOS netstat output
fn parse_macos_netstat_output(output: &str, services: &mut Vec<NetworkService>) {
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let protocol = if parts[0].contains("tcp") { "TCP" } else { "UDP" };
        let local_addr = parts[3];
        let remote_addr = parts[4];
        let state = parts[5];

        if state.eq_ignore_ascii_case("listen") || state.eq_ignore_ascii_case("established") {
            services.push(NetworkService {
                protocol: protocol.to_string(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: state.to_string(),
                service_name: "Unknown".to_string(),
            });
        }
    }
}

/// Parse Windows netstat output
fn parse_windows_netstat_output(output: &str, services: &mut Vec<NetworkService>) {
    for line in output.lines().skip(4) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let protocol = parts[0];
        let local_addr = parts[1];
        let remote_addr = parts[2];
        let state = parts[3];

        if state.eq_ignore_ascii_case("listening") {
            services.push(NetworkService {
                protocol: protocol.to_uppercase(),
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                state: "LISTEN".to_string(),
                service_name: "Unknown".to_string(),
            });
        }
    }
}

/// Parse lsof output (lsof -i -P -n)
fn parse_lsof_output(output: &str, services: &mut Vec<NetworkService>) {
    for line in output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        // lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // where NAME contains protocol info like "TCP *:8080 (LISTEN)"
        let name = parts[8];

        if name.contains("LISTEN") || name.contains("ESTABLISHED") || name.contains("*:") {
            let protocol = if name.starts_with("TCP") || name.starts_with("IPv4") { "TCP" } else if name.starts_with("UDP") { "UDP" } else { "UNKNOWN" };

            // Extract local address from NAME field
            let local_addr = if let Some(pos) = name.find("*:") {
                name[pos..].to_string()
            } else if let Some(pos) = name.find("127.") {
                name[pos..].to_string()
            } else {
                name.to_string()
            };

            let state = if name.contains("LISTEN") {
                "LISTEN"
            } else if name.contains("ESTABLISHED") {
                "ESTABLISHED"
            } else {
                "UNKNOWN"
            };

            services.push(NetworkService {
                protocol: protocol.to_string(),
                local_addr,
                remote_addr: "-".to_string(),
                state: state.to_string(),
                service_name: "Unknown".to_string(),
            });
        }
    }
}

/// Extract port number from address string (e.g., "127.0.0.1:8080" -> "8080")
fn extract_port(addr: &str) -> Option<u16> {
    addr.split(':')
        .last()
        .and_then(|p| p.parse::<u16>().ok())
}

/// Create a mapping of common ports to service names
fn create_service_map() -> HashMap<u16, &'static str> {
    let mut map = HashMap::new();

    // HTTP/HTTPS
    map.insert(80, "HTTP");
    map.insert(443, "HTTPS");
    map.insert(8080, "HTTP-Alt");
    map.insert(8443, "HTTPS-Alt");

    // Mail
    map.insert(25, "SMTP");
    map.insert(587, "SMTP-TLS");
    map.insert(110, "POP3");
    map.insert(995, "POP3S");
    map.insert(143, "IMAP");
    map.insert(993, "IMAPS");

    // DNS / Network
    map.insert(53, "DNS");
    map.insert(67, "DHCP");
    map.insert(123, "NTP");

    // SSH / Remote
    map.insert(22, "SSH");
    map.insert(3389, "RDP");
    map.insert(5900, "VNC");

    // Databases
    map.insert(3306, "MySQL");
    map.insert(5432, "PostgreSQL");
    map.insert(27017, "MongoDB");
    map.insert(6379, "Redis");
    map.insert(27017, "MongoDB");
    map.insert(5984, "CouchDB");

    // FTP / SFTP
    map.insert(21, "FTP");
    map.insert(990, "FTPS");
    map.insert(115, "SFTP");

    // Other services
    map.insert(445, "SMB");
    map.insert(139, "NetBIOS");
    map.insert(161, "SNMP");
    map.insert(389, "LDAP");
    map.insert(3128, "Squid-Proxy");
    map.insert(8888, "Proxy-Alt");
    map.insert(9200, "Elasticsearch");
    map.insert(27017, "MongoDB");
    map.insert(50070, "Hadoop-NameNode");

    map
}

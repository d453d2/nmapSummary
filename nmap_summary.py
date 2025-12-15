import argparse
import glob
import xml.etree.ElementTree as ET
import csv
import json
import os

WEB_PORTS = {"80", "443", "8080", "8000", "8443"}
WEB_SERVICES = {"http", "https", "ssl/http"}

WEAK_SERVICES = {
    "ftp", "telnet", "rlogin", "snmp", "redis",
    "mysql", "postgres", "vnc",
    "rdp", "smb", "netbios-ssn"
}

DB_SERVICES = {"mysql", "postgres"}
SMB_SERVICES = {"smb", "netbios-ssn"}

def parse_nmap_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        data = {
            "ip": None,
            "hostnames": [],
            "os": None,
            "tcp_ports": [],
            "udp_ports": []
        }

        for addr in host.findall("address"):
            if addr.attrib.get("addrtype") in ("ipv4", "ipv6"):
                data["ip"] = addr.attrib.get("addr")

        for hn in host.findall("hostnames/hostname"):
            data["hostnames"].append(hn.attrib.get("name"))

        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            data["os"] = osmatch.attrib.get("name")

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            protocol = port.attrib.get("protocol")
            portid = port.attrib.get("portid")

            svc = port.find("service")
            service_name = svc.attrib.get("name") if svc is not None else ""

            port_data = {
                "port": portid,
                "service": service_name,
                "product": svc.attrib.get("product", "") if svc is not None else "",
                "version": svc.attrib.get("version", "") if svc is not None else "",
                "weak": service_name in WEAK_SERVICES
            }

            if protocol == "tcp":
                data["tcp_ports"].append(port_data)
            elif protocol == "udp":
                data["udp_ports"].append(port_data)

        hosts.append(data)
    return hosts

def merge_hosts(all_hosts):
    hosts_dict = {}
    for h in all_hosts:
        ip = h["ip"]
        if ip in hosts_dict:
            existing = hosts_dict[ip]
            existing["hostnames"] = list(set(existing["hostnames"] + h["hostnames"]))
            existing["tcp_ports"].extend(h["tcp_ports"])
            existing["udp_ports"].extend(h["udp_ports"])
            if not existing["os"] and h["os"]:
                existing["os"] = h["os"]
        else:
            hosts_dict[ip] = h
    return list(hosts_dict.values())

def dedupe_ports(hosts):
    for h in hosts:
        seen_tcp = set()
        new_tcp = []
        for p in h["tcp_ports"]:
            if p["port"] not in seen_tcp:
                new_tcp.append(p)
                seen_tcp.add(p["port"])
        h["tcp_ports"] = sorted(new_tcp, key=lambda x: int(x["port"]))

        seen_udp = set()
        new_udp = []
        for p in h["udp_ports"]:
            if p["port"] not in seen_udp:
                new_udp.append(p)
                seen_udp.add(p["port"])
        h["udp_ports"] = sorted(new_udp, key=lambda x: int(x["port"]))

def filter_hosts_by_target_protocol(hosts, targets=None, protocol=None):
    target_set = set(targets.split(",")) if targets else None
    filtered = []

    for h in hosts:
        if target_set and h["ip"] not in target_set:
            continue

        new_h = {
            "ip": h["ip"],
            "hostnames": h["hostnames"],
            "os": h["os"],
            "tcp_ports": h["tcp_ports"] if protocol in (None, "tcp") else [],
            "udp_ports": h["udp_ports"] if protocol in (None, "udp") else []
        }

        filtered.append(new_h)
    return filtered

def print_console_summary(hosts, file_count, targets=None, protocol=None):
    compact = targets or protocol  # compact mode if filtering is active

    if not compact:
        print(f"\n[+] XML files processed: {file_count}")
        print(f"[+] Hosts found: {len(hosts)}\n")

    for h in hosts:
        name = f"({','.join(h['hostnames'])})" if h["hostnames"] else ""
        tcp_ports = ",".join(p["port"] for p in h["tcp_ports"]) or "none"
        udp_ports = ",".join(p["port"] for p in h["udp_ports"]) or "none"

        if compact:
            if protocol == "tcp":
                print(f"{h['ip']}{name} TCP:{tcp_ports}")
            elif protocol == "udp":
                print(f"{h['ip']}{name} UDP:{udp_ports}")
            else:  # target filtered but protocol not specified
                print(f"{h['ip']}{name} TCP:{tcp_ports}")
                print(f"{h['ip']}{name} UDP:{udp_ports}")
        else:
            print(f"Host: {h['ip']}{name}")
            if protocol in (None, "tcp"):
                print(f"  TCP Open Ports: {tcp_ports}")
            if protocol in (None, "udp"):
                print(f"  UDP Open Ports: {udp_ports}")
            print()


def generate_csv(hosts, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "hostnames", "protocol", "ports", "os"])
        for h in hosts:
            writer.writerow([
                h["ip"],
                ",".join(h["hostnames"]),
                "tcp",
                ",".join(p["port"] for p in h["tcp_ports"]),
                h["os"]
            ])
            writer.writerow([
                h["ip"],
                ",".join(h["hostnames"]),
                "udp",
                ",".join(p["port"] for p in h["udp_ports"]),
                h["os"]
            ])

def generate_html_interactive(hosts, path, file_count):
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Nmap Summary Interactive Report</title>
<style>
body {{ font-family: Arial; background:#111; color:#eee; }}
details {{ margin: 10px 0; border: 1px solid #444; padding: 5px; }}
summary {{ font-weight: bold; cursor: pointer; }}
.weak {{ color:#ff6666; font-weight:bold; }}
.web {{ color:#66ccff; font-weight:bold; }}
.db {{ color:#66ff66; font-weight:bold; }}
.smb {{ color:#ff9900; font-weight:bold; }}
.hidden {{ display:none; }}
input {{ margin:5px; padding:5px; width:200px; }}
</style>
</head>
<body>
<h1>Nmap Summary Interactive Report</h1>
<p>Scans processed: {file_count}</p>

<input type="text" id="searchBox" placeholder="Search hosts or ports..." onkeyup="filterHosts()">
<br>
<label><input type="checkbox" id="webFilter" onchange="filterHosts()"> Show only Web hosts</label>
<label><input type="checkbox" id="weakFilter" onchange="filterHosts()"> Show only Weak services</label>

<script>
function filterHosts() {{
    let search = document.getElementById("searchBox").value.toLowerCase();
    let webOnly = document.getElementById("webFilter").checked;
    let weakOnly = document.getElementById("weakFilter").checked;
    let hosts = document.querySelectorAll("details");
    hosts.forEach(function(h) {{
        let text = h.innerText.toLowerCase();
        let webMatch = !webOnly || h.querySelector(".web") !== null;
        let weakMatch = !weakOnly || h.querySelector(".weak") !== null;
        if (text.includes(search) && webMatch && weakMatch) {{
            h.classList.remove("hidden");
        }} else {{
            h.classList.add("hidden");
        }}
    }});
}}
</script>
"""

    for h in hosts:
        host_name = f"{h['ip']} ({', '.join(h['hostnames'])})" if h["hostnames"] else h['ip']
        html += f"<details><summary>{host_name}</summary>"
        if h["os"]:
            html += f"<p>OS: {h['os']}</p>"

        html += "<h3>TCP Open Ports</h3><ul>"
        for p in h["tcp_ports"]:
            cls = ""
            if p["weak"]:
                cls = "weak"
            elif p["service"] in {"http","https"}:
                cls = "web"
            elif p["service"] in DB_SERVICES:
                cls = "db"
            elif p["service"] in SMB_SERVICES:
                cls = "smb"
            html += f"<li class='{cls}'>{p['port']} — {p['service']} {p['product']} {p['version']}</li>"
        html += "</ul>"

        html += "<h3>UDP Open Ports</h3><ul>"
        for p in h["udp_ports"]:
            cls = ""
            if p["weak"]:
                cls = "weak"
            elif p["service"] in {"http","https"}:
                cls = "web"
            elif p["service"] in DB_SERVICES:
                cls = "db"
            elif p["service"] in SMB_SERVICES:
                cls = "smb"
            html += f"<li class='{cls}'>{p['port']} — {p['service']} {p['product']} {p['version']}</li>"
        html += "</ul></details>"

    html += "</body></html>"

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

def main():
    parser = argparse.ArgumentParser(description="Advanced Nmap result summarizer")
    parser.add_argument("input", nargs="+", help="One or more Nmap XML files or globs")
    parser.add_argument("--csv", help="Write CSV output")
    parser.add_argument("--html", help="Write HTML report")
    parser.add_argument("--web-only", action="store_true")
    parser.add_argument("--weak-only", action="store_true")
    parser.add_argument("--json", help="Write JSON output")
    parser.add_argument("-t", "--target", help="Filter output for specific host(s) (comma-separated)")
    parser.add_argument("-p", "--protocol", choices=["tcp","udp"], help="Filter output by protocol")

    args = parser.parse_args()

    files = []
    for item in args.input:
        files.extend(glob.glob(item))
    files = sorted(set(files))
    if not files:
        parser.error("No XML files found")

    all_hosts = []
    valid_files = 0
    for f in files:
        if not os.path.isfile(f) or os.path.getsize(f) == 0:
            print(f"[!] Skipping empty or missing file: {f}")
            continue
        try:
            hosts = parse_nmap_xml(f)
            all_hosts.extend(hosts)
            valid_files += 1
        except ET.ParseError as e:
            print(f"[!] Failed to parse {f}: {e}")

    all_hosts = merge_hosts(all_hosts)
    dedupe_ports(all_hosts)

    if args.web_only:
        for h in all_hosts:
            h["tcp_ports"] = [p for p in h["tcp_ports"] if p["port"] in WEB_PORTS or p["service"] in WEB_SERVICES]

    if args.weak_only:
        for h in all_hosts:
            h["tcp_ports"] = [p for p in h["tcp_ports"] if p["weak"]]
            h["udp_ports"] = [p for p in h["udp_ports"] if p["weak"]]

    # Apply unified target/protocol filtering
    filtered_hosts = filter_hosts_by_target_protocol(all_hosts, targets=args.target, protocol=args.protocol)

    # Console output
    print_console_summary(filtered_hosts, valid_files, targets=args.target, protocol=args.protocol)

    # CSV output
    if args.csv:
        generate_csv(filtered_hosts, args.csv)
        print(f"[+] CSV written to {args.csv}")

    # HTML output
    if args.html:
        generate_html_interactive(filtered_hosts, args.html, valid_files)
        print(f"[+] Interactive HTML report written to {args.html}")

    # JSON output
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(filtered_hosts, f, indent=2)
        print(f"[+] JSON written to {args.json}")

if __name__ == "__main__":
    main()

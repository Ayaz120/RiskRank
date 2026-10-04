"""
parsers/nmap_parser.py
----------------------
Parses Nmap XML output (`nmap -oX output.xml`) into normalized findings.
"""

import xml.etree.ElementTree as ET


def parse_nmap_xml(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()
    findings = []

    for host in root.findall("host"):
        address_el = host.find("address")
        ip = address_el.get("addr") if address_el is not None else "unknown"

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = port.get("portid")
            protocol = port.get("protocol")

            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else ""
            version = service_el.get("version") if service_el is not None else ""

            description_parts = [p for p in [product, version] if p]
            description = " ".join(description_parts) if description_parts else "No version info detected"

            findings.append({
                "asset": ip,
                "title": f"Open port {port_id}/{protocol} ({service_name})",
                "description": description,
                "raw_data": {
                    "ip": ip, "port": port_id, "protocol": protocol,
                    "service": service_name, "product": product, "version": version,
                },
            })

    return findings


if __name__ == "__main__":
    import sys
    for r in parse_nmap_xml(sys.argv[1]):
        print(r)

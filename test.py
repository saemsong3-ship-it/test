import json
from collections import defaultdict, deque

# -----------------------------
# 1. OSV 결과 파싱
# -----------------------------
def parse_osv_results(file_path, cvss_threshold=7.0):
    vuln_map = {}

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("URL"):
                continue

            parts = line.split("|")
            if len(parts) < 6:
                continue

            url, cvss, ecosystem, package, version, source = parts

            try:
                cvss = float(cvss)
            except:
                continue

            if cvss >= cvss_threshold:
                key = f"{package}@{version}"
                vuln_map[key] = {
                    "cvss": cvss,
                    "url": url
                }

    return vuln_map


# -----------------------------
# 2. SBOM 파싱
# -----------------------------
def parse_sbom(sbom_path):
    with open(sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)

    dependencies = sbom.get("dependencies", [])
    components = sbom.get("components", [])

    graph = defaultdict(list)
    purl_to_name = {}

    for comp in components:
        purl = comp.get("purl")
        name = comp.get("name")
        version = comp.get("version")

        if purl:
            purl_to_name[purl] = f"{name}@{version}"

    for dep in dependencies:
        ref = dep.get("ref")
        depends_on = dep.get("dependsOn", [])

        if ref in purl_to_name:
            src = purl_to_name[ref]

            for d in depends_on:
                if d in purl_to_name:
                    dst = purl_to_name[d]
                    graph[src].append(dst)

    return graph


# -----------------------------
# 3. 모든 dependency path 추출
# -----------------------------
def get_all_paths(graph):
    all_paths = []

    all_nodes = set(graph.keys())
    all_deps = set(d for deps in graph.values() for d in deps)
    roots = all_nodes - all_deps

    for root in roots:
        queue = deque([(root, [root])])

        while queue:
            node, path = queue.popleft()

            # leaf node
            if node not in graph or not graph[node]:
                all_paths.append(path)
                continue

            for next_node in graph[node]:
                if next_node not in path:
                    queue.append((next_node, path + [next_node]))

    return all_paths


# -----------------------------
# 4. 결과 생성
# -----------------------------
def analyze(sbom_file, osv_file, output_file):
    vuln_map = parse_osv_results(osv_file)
    graph = parse_sbom(sbom_file)

    paths = get_all_paths(graph)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("DEPENDENCY_PATH,VULNERABLE,CVSS,URL\n")

        for path in paths:
            vuln_found = False
            max_cvss = 0
            vuln_url = ""

            for node in path:
                if node in vuln_map:
                    vuln_found = True
                    if vuln_map[node]["cvss"] > max_cvss:
                        max_cvss = vuln_map[node]["cvss"]
                        vuln_url = vuln_map[node]["url"]

            f.write(f"{' -> '.join(path)},{vuln_found},{max_cvss},{vuln_url}\n")

    print(f"[+] Done. Output: {output_file}")


# -----------------------------
# 실행
# -----------------------------
if __name__ == "__main__":
    sbom_file = "sbom.json"
    osv_file = "osv_scanner_result.txt"
    output_file = "dependency_paths_result.csv"

    analyze(sbom_file, osv_file, output_file)
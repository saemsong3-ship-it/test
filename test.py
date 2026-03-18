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
                key = f"{package.strip()}@{version.strip()}"
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
        group = comp.get("group")

        if group:
            key = f"{group}:{name}@{version}"
        else:
            key = f"{name}@{version}"

        if purl:
            purl_to_name[purl] = key

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
# 3. 매칭 로직
# -----------------------------
def is_match(sbom_key, osv_key):
    if sbom_key == osv_key:
        return True

    sbom_name = sbom_key.split(":")[-1]
    if sbom_name == osv_key:
        return True

    return False


# -----------------------------
# 4. 특정 취약점 경로 찾기
# -----------------------------
def find_paths_to_target(graph, target):
    paths = []

    all_nodes = set(graph.keys())
    all_deps = set(d for deps in graph.values() for d in deps)
    roots = all_nodes - all_deps

    for root in roots:
        queue = deque([(root, [root])])

        while queue:
            node, path = queue.popleft()

            if is_match(node, target):
                paths.append(path)
                continue

            if node in graph:
                for next_node in graph[node]:
                    if next_node not in path:
                        queue.append((next_node, path + [next_node]))

    return paths


# -----------------------------
# 5. 분석 (핵심)
# -----------------------------
def analyze(sbom_file, osv_file, output_file):
    vuln_map = parse_osv_results(osv_file)
    graph = parse_sbom(sbom_file)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("PACKAGE,VERSION,CVSS,URL,DEPENDENCY_PATH\n")

        for osv_key, info in vuln_map.items():
            paths = find_paths_to_target(graph, osv_key)

            # 👉 SBOM에 없는 취약점은 제외
            if not paths:
                continue

            pkg, ver = osv_key.split("@")

            for path in paths:
                f.write(f"{pkg},{ver},{info['cvss']},{info['url']},{' -> '.join(path)}\n")

    print(f"[+] Done. Output: {output_file}")


# -----------------------------
# 실행
# -----------------------------
if __name__ == "__main__":
    sbom_file = "sbom.json"
    osv_file = "osv_scanner_result.txt"
    output_file = "filtered_vuln_paths.csv"

    analyze(sbom_file, osv_file, output_file)
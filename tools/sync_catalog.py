"""Read the 49-policy reference workbook and regenerate the policy catalog."""

import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_URL = "https://docs.google.com/spreadsheets/d/1IrvVFRUNMCF3WGOyGyeo0hpzDWO7zmCi/edit?gid=186190064#gid=186190064"
SOURCE_SHEET = "정책 최종본의 사본"
MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"

REQUEST_IDS = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    21, 23, 36, 37, 38, 39, 41,
}
RESPONSE_IDS = {20, 35}
ACTIVATION_IDS = {1, 2, *range(25, 35)}
OPERATION_IDS = {22, 40, 42, 43, 44}
RETIREMENT_IDS = {24, *range(45, 50)}


def source_rows(source: pathlib.Path):
    with zipfile.ZipFile(source) as archive:
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relations = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        target_by_id = {
            node.attrib["Id"]: node.attrib["Target"]
            for node in relations.findall(f"{PKG_REL}Relationship")
        }
        sheet = next(
            (node for node in workbook.findall(f"{MAIN}sheets/{MAIN}sheet")
             if node.attrib["name"] == SOURCE_SHEET),
            None,
        )
        if sheet is None:
            raise SystemExit(f"Missing sheet: {SOURCE_SHEET}")
        target = target_by_id[sheet.attrib[f"{REL}id"]].lstrip("/")
        if not target.startswith("xl/"):
            target = "xl/" + target
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            strings = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = [
                "".join(part.text or "" for part in node.iter(f"{MAIN}t"))
                for node in strings.findall(f"{MAIN}si")
            ]
        page = ET.fromstring(archive.read(target))
        for row in page.findall(f"{MAIN}sheetData/{MAIN}row"):
            values = [None] * 8
            for cell in row.findall(f"{MAIN}c"):
                letters = re.match(r"[A-Z]+", cell.attrib["r"]).group()
                index = 0
                for letter in letters:
                    index = index * 26 + ord(letter) - 64
                if index > len(values):
                    continue
                kind = cell.attrib.get("t")
                if kind == "inlineStr":
                    node = cell.find(f"{MAIN}is")
                    value = "".join(part.text or "" for part in node.iter(f"{MAIN}t")) if node is not None else None
                else:
                    node = cell.find(f"{MAIN}v")
                    value = node.text if node is not None else None
                    if kind == "s" and value is not None:
                        value = shared[int(value)]
                values[index - 1] = value
            yield int(row.attrib["r"]), values


def main(source: pathlib.Path) -> None:
    all_modes = REQUEST_IDS | RESPONSE_IDS | ACTIVATION_IDS | OPERATION_IDS | RETIREMENT_IDS
    if all_modes != set(range(1, 50)):
        raise SystemExit("Policy stage mapping is incomplete")
    controls = []
    for row_number, row in source_rows(source):
        if not isinstance(row[0], str) or not re.fullmatch(r"PAC\d{2}", row[0]):
            continue
        number = int(row[0][3:])
        stage = "request" if number in REQUEST_IDS else "response" if number in RESPONSE_IDS else "external"
        attestation_stage = (
            "activation" if number in ACTIVATION_IDS else
            "operation" if number in OPERATION_IDS else
            "retirement" if number in RETIREMENT_IDS else None
        )
        controls.append({
            "id": row[0],
            "area": row[1],
            "name": row[2],
            "policy": row[5],
            "explanation": row[6],
            "evaluation": stage,
            "attestation_stage": attestation_stage,
            "source_row": row_number,
        })
    expected = [f"PAC{i:02d}" for i in range(1, 50)]
    if [c["id"] for c in controls] != expected:
        raise SystemExit("Source does not contain PAC01 through PAC49 in order")
    data = {
        "catalog_version": "pac49-v1",
        "source_url": SOURCE_URL,
        "source_sheet": SOURCE_SHEET,
        "controls": controls,
    }
    target = ROOT / "catalog" / "controls.json"
    target.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {len(controls)} controls to {target}")
    print(f"Rego request: {len(REQUEST_IDS)}, Rego response: {len(RESPONSE_IDS)}, external: {49-len(REQUEST_IDS)-len(RESPONSE_IDS)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python3 tools/sync_catalog.py SOURCE.xlsx")
    main(pathlib.Path(sys.argv[1]))

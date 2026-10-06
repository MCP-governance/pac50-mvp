"""Build the 49-row review list and the external-evidence checklist."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
catalog = json.loads((ROOT / "catalog" / "controls.json").read_text())
controls = catalog["controls"]
mode_label = {
    "request": "요청 전 Rego",
    "response": "응답 전 Rego",
}
external_label = {
    "activation": "도입 및 등록 증적",
    "operation": "운영 증적",
    "retirement": "폐기 증적",
}

lines = [
    "# PAC01부터 PAC49까지 정책 목록",
    "",
    f"기준: [원본 정책표]({catalog['source_url']})의 `{catalog['source_sheet']}` 시트. "
    "원문 정책 내용과 설명은 [기계 판독 목록](catalog/controls.json)에 있다.",
    "",
    "요청 전 또는 응답 전 Rego는 제공된 검증 사실을 판정한다. 외부 정책의 Rego 관문은 "
    "증적 상태와 범위를 확인하며 실제 절차의 수행 여부는 별도 시스템, 시험 또는 사람이 확인한다.",
    "",
    "| ID | 영역 | 정책명 | 검증 단계 |",
    "| --- | --- | --- | --- |",
]
for control in controls:
    lines.append(
        f"| {control['id']} | {control['area']} | {control['name']} | "
        f"{mode_label.get(control['evaluation'], external_label.get(control['attestation_stage']))} |"
    )
(ROOT / "REGO_POLICY_LIST.md").write_text("\n".join(lines) + "\n")

evidence = {
    "PAC01": "배포처, 배포자, 버전과 서명 또는 해시 검증 기록",
    "PAC02": "기능, 목적, 데이터, 권한과 전송 범위 도입 승인 기록",
    "PAC22": "호출 및 권한 변경 로그, 보존 설정과 정기 검토 기록",
    "PAC24": "토큰과 API 키 회수, 재접근 시험 기록",
    "PAC25": "제공자의 유지보수 및 보안 업데이트 지원 확인 기록",
    "PAC26": "Tool 설명과 입력 스키마의 악성 지시 검토 기록",
    "PAC27": "Tool 설명과 실제 조회, 변경, 전송 동작 비교 시험",
    "PAC28": "Prompt 템플릿 본문과 변수 검토 기록",
    "PAC29": "외부 제공자의 저장, 재사용, 처리 위치, 삭제 조건 검토",
    "PAC30": "OAuth 반환 주소, 발급자, 요청 상태 및 재사용 응답 시험",
    "PAC31": "비밀정보 보관소와 설정, 실행 인자, 오류 메시지 점검",
    "PAC32": "Server별 분리된 인증정보와 사용 범위 설정",
    "PAC33": "암호화 전송과 연결 상대 검증 설정 및 연결 시험",
    "PAC34": "로컬 실행 파일, 인자, 환경변수의 승인 설정 대조",
    "PAC40": "취약점 영향 평가, 수정 기한과 격리 또는 중지 기록",
    "PAC42": "인증정보 교체와 이전 값 무효화, 재접근 시험",
    "PAC43": "새 Tool, 미승인 연결, 호출 증가 경보의 작동 시험",
    "PAC44": "탐지 후 연결 중지, 조사, 인증정보 교체와 복구 기록",
    "PAC45": "잔존 프로세스와 자동 실행 항목 종료 및 재시작 시험",
    "PAC46": "문서 저장소 계정과 공유 권한 회수 및 조회 시험",
    "PAC47": "문서 사본, 임시 파일, 캐시 삭제와 결과 확인",
    "PAC48": "외부 제공자 보유 문서의 삭제 또는 반환 확인",
    "PAC49": "백업 복원 후 폐기 연결, Tool 승인, 인증정보 재활성화 시험",
}
external = [c for c in controls if c["evaluation"] == "external"]
assert {c["id"] for c in external} == set(evidence)
lines = [
    "# 외부 절차와 증적 확인 목록",
    "",
    "이 23개 항목은 Rego가 증적 레코드의 상태와 범위를 확인하지만, 증적 내용의 진위와 "
    "실제 수행 여부는 별도로 검증해야 한다. 아래 내용은 필요한 확인 자료이며 현재 모두 미검증이다.",
    "",
    "| ID | 정책명 | 확인할 자료 | 현재 상태 |",
    "| --- | --- | --- | --- |",
]
for control in external:
    lines.append(
        f"| {control['id']} | {control['name']} | {evidence[control['id']]} | 미검증 |"
    )
(ROOT / "EXTERNAL_CONTROL_CHECKLIST.md").write_text("\n".join(lines) + "\n")
print(f"Wrote {len(controls)} catalog rows and {len(external)} external checks")

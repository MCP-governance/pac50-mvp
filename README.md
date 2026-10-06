# MCP Gateway PAC50 검증 초안

이 폴더는 [50개 정책 원본](https://docs.google.com/spreadsheets/d/1NGFWTI_TNnUiDPHupOIfEOyfcB9h5ecM/edit?gid=715752554#gid=715752554)의 `(본)정책 최종본` 시트를 기준으로 한다. 원본의 `POL-01`부터 `POL-50`까지를 같은 번호의 `PAC01`부터 `PAC50`까지로 표기한다. 문서용 시트는 순서와 마지막 행의 내용이 달라 기준으로 사용하지 않았다.

## 현재 구현 범위

| 구분 | 수 | 내용 |
| --- | ---: | --- |
| 전체 정책 목록 | 50 | 원본의 영역, 정책명, 정책 내용과 행 번호를 `catalog/controls.json`에 보존 |
| 요청 전 Rego 판정 | 25 | 연결, HTTP 출처, 신원, 권한, 인자, 데이터, 전송, 승인, 호출 제한, 변경 등 |
| 응답 전 Rego 판정 | 2 | PAC31 민감정보 노출, PAC32 중요 문서에 쓸 응답의 출처와 내용 |
| 외부 절차와 증적 | 23 | 도입, 운영, 폐기의 증적 상태와 적용 범위를 단계별 Rego 관문에서 검사. [확인 목록](EXTERNAL_CONTROL_CHECKLIST.md) 참조 |

Rego의 `ALLOW`는 제공된 사실을 바탕으로 해당 단계의 규칙을 통과했다는 뜻이다. 외부 단계에서 `ALLOW`를 받더라도 증적 원문이 진짜인지, 해당 정책을 실제로 수행했는지는 별도로 확인해야 한다. 현재 23개 외부 정책의 실제 증적은 제공되지 않아 모두 미검증이다. 이 폴더에는 Gateway, MCP Server, 인증 시스템, 승인 대장, 증적 저장소 구현이 없다.

## 파일

| 파일 | 용도 |
| --- | --- |
| [`catalog/controls.json`](catalog/controls.json) | 원본 50개 정책과 자동 판정 단계 |
| [`REGO_POLICY_LIST.md`](REGO_POLICY_LIST.md) | 50개 정책별 구현 범위 |
| [`policy/pac50.rego`](policy/pac50.rego) | 요청과 응답 단계 규칙 |
| [`policy/external.rego`](policy/external.rego) | 도입, 운영, 폐기 단계 증적 관문 |
| [`policy/decision.rego`](policy/decision.rego) | `DENY > APPROVAL > ALLOW` 통합 판정 |
| [`schema/input.schema.json`](schema/input.schema.json) | 입력 자료형 선언 |
| [`examples/allow.json`](examples/allow.json) | 합성된 정상 요청 |
| [`tests/run.py`](tests/run.py) | 정상, 거부, 승인 대기, 경계 사례 |
| [`PAC_DESIGN.md`](PAC_DESIGN.md) | 판정 경계와 각 단계의 책임 |
| [`GATEWAY_INTEGRATION.md`](GATEWAY_INTEGRATION.md) | Gateway 연결 및 통합 시험 순서 |

## 실행

[OPA 공식 설치 안내](https://www.openpolicyagent.org/docs/latest/#running-opa)에 따라 OPA를 준비하고 이 폴더에서 실행한다.

```sh
opa check --schema schema/input.schema.json policy
opa eval --format=pretty --input examples/allow.json --data policy data.mcp.decision.decision
python3 tests/run.py
```

응답 판정은 `phase`를 `response`로 바꾸고 `facts.response`에 검증된 응답 정보를 넣어 같은 결정 경로를 평가한다. 외부 정책은 `activation`, `operation`, `retirement` 단계에서 각 정책 ID의 `facts.attestations`를 확인한다. 증적 레코드에는 검증 여부, 통과 여부, 서버 범위, 증적 참조, 점검 시각과 만료 시각이 필요하다. Gateway는 `DENY`, `APPROVAL`, OPA 오류, 타임아웃, 응답 누락 시 요청 또는 응답을 전달하지 않아야 한다.

원본 목록을 다시 동기화하려면 `python3 tools/sync_catalog.py SOURCE.xlsm`를 실행한다. 이 스크립트는 50개 ID의 순서와 누락 여부를 검증한다. 예시 입력의 필드가 바뀌면 `python3 tools/build_schema.py`로 형식 선언을 갱신한다.

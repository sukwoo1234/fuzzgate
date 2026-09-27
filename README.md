# FuzzGate

Format-Aware Fuzzing for AI Model File Loaders

> 퍼징으로 찾는 데서 끝내지 않고,
> 재현·검증·트리아지·리포트까지 연결하는 보안 검증 도구입니다.

## 구현 상태 (브랜치별)
기본 `main`과 [개발 브랜치 `docs/specs-readme`](https://github.com/sukwoo1234/fuzzgate/tree/docs/specs-readme)의 구현 범위는 다르다. 아래 개발 상태는 [2026-09-27 검증 HEAD `12123c7`](https://github.com/sukwoo1234/fuzzgate/tree/12123c71196d05c02a22f59673ca1ccc14c1367f) 기준이다.

| 항목 | 기본 `main` | 개발 브랜치 `12123c7` |
| --- | --- | --- |
| `run`, `report`, 포맷 사전 검사·로더 호출 | 실행 경로 구현 | 기능 확장 중. 실환경 결과는 실행 로그로 확인 |
| AFL++·libFuzzer 연동 | 명령 어댑터 구현 | 실행 경로 구현. 성능 지표는 별도 검증 필요 |
| 포맷 구조/필드 기반 corpus mutator | 없음 | ONNX·GGUF·safetensors용 CLI 구현. 완전한 문법 보존 인프로세스 custom mutator와는 구분 |
| 3회 `triage`·스택 서명 비교 | 이전 판정 로직 | 코드 구현. 정상 ONNX 입력에서 `clean_count=3`, `crashed_count=0`, `not_reproduced` 확인; 비공개 크래시 PoC 검증은 남음 |
| 규칙 기반 crash severity·CVSS 후보 | 없음 | 구현. 사람이 최종 확인하는 보수적 제안 |
| 레지스터·PC 제어 기반 RCE 등급화 | 계획 | 계획 |
| LLM 보조 | 설계 | 정책·설계 단계, 실행 경로에 연결되지 않음 |

개발 브랜치의 [mutator 코드](https://github.com/sukwoo1234/fuzzgate/tree/docs/specs-readme/src/mutate), [triage 코드](https://github.com/sukwoo1234/fuzzgate/blob/docs/specs-readme/src/triage.rs), [severity 제안 코드](https://github.com/sukwoo1234/fuzzgate/blob/docs/specs-readme/src/report.rs)를 근거로 구분했다. 정상 ONNX 실행 결과는 사용자 WSL 검증 기록이다.

## 먼저 읽기
- 설계/결정: [first.md](first.md)
- 구현 명세: [docs/specs.md](docs/specs.md)
- 유효 코퍼스 준비: [docs/corpus-sop.md](docs/corpus-sop.md)

## 차별점과 남은 검증
- **Deep & Structured Fuzzing**: 개발 브랜치에 포맷 구조/필드 기반 corpus mutator가 있다. 완전한 문법 보존 인프로세스 custom mutator는 향후 범위다.
- **Auto-Verification**: 개발 브랜치에 3회 triage와 스택 서명 비교가 구현되어 있다. 비공개 크래시 PoC를 통한 최종 검증은 남아 있다.
- **Exploitability Triage**: 규칙 기반 crash severity·CVSS 후보 제안은 구현되어 있다. 레지스터·PC 제어 분석을 통한 RCE 가능성 등급화는 계획 단계다.
- **Reproducibility by Design**: 입력 해시와 실행 환경을 기록하고, 같은 조건에서 재현률을 측정하는 것이 목표다.
- **LLM Assist (Out of Loop)**: 퍼징 루프 밖에서 Seed/Dictionary/Mutation guide를 보조하는 기능은 계획 단계다.

### 목표 (Goals)
- 구조 인지형 mutator/harness로 더 깊은 경로를 타겟한다.
- 기존 툴 대비 재현 성공률/제출 승인률을 수치로 개선한다.
- 차별점 근거 지표 체크리스트: [docs/roadmap.md](docs/roadmap.md) `차별점 검증 체크리스트 (릴리즈 이후)`

## RCE 후보 검토 범위
- 하네스/뮤테이터/triage의 목표 정책은 [first.md](first.md)와 [docs/specs.md](docs/specs.md)에 정리되어 있다.
- **Format-Aware Mutator**: 개발 브랜치에 ONNX·GGUF·safetensors의 구조/필드 기반 corpus mutation CLI가 구현되어 있다.
- **Targeted Harness**: 현재 포맷 사전 검사와 외부 로더 호출 경로가 있으며, 깊은 파싱 경로 도달 여부는 실행 결과로 확인해야 한다.
- **Exploitability Triage**: 레지스터/스택/PC 오염 분석과 RCE 후보 등급화는 구현 계획이다.

## 핵심 목표
- 대상 포맷: **GGUF / ONNX / safetensors**
- 유효 버그 기준: **SEGV/Abort + 동일 입력 3회 재현 + 상위 3프레임 동일**
- 자동화 범위: **퍼징 실행 → 크래시 감지 → 재현 검증 → 리포트 초안 생성**

## 시스템 아키텍처 (설계)
- Fuzz Manager: 컨테이너 실행/헬스/재시작 관리
- Job Queue: 파일 기반 작업 분배/상태 전이
- Artifact Store: 크래시/재현/증거 번들 저장

## 문서 가이드
- 설계/결정: [first.md](first.md)
- 구현 명세: [docs/specs.md](docs/specs.md)
- 문서 TODO: [docs/todo.md](docs/todo.md)
- 개발 로드맵: [docs/roadmap.md](docs/roadmap.md)
- 리포트 샘플: [docs/report-sample.md](docs/report-sample.md)
- 유효 코퍼스 SOP: [docs/corpus-sop.md](docs/corpus-sop.md)

## CLI (`main` 기준)
- `tool run`, `tool triage`, `tool report`: 실행 경로가 있다. 개발 브랜치는 별도의 triage 판정 로직을 사용한다.
- `list`, `show <id>`, `export <id>`: 기본 `main`에서는 출력용 명령 골격이다.

## 기본 경로
- 데이터: `./data`
- 시드: `./seeds`

## Fuzz Host 준비(의존성 설치)

새 퍼징 PC/WSL에서는 `git clone`만으로 시스템 의존성이 설치되지 않는다.
아래 스크립트로 호스트 의존성을 먼저 맞춘다.

```bash
bash scripts/setup_fuzz_host.sh
# docker 제외 시
bash scripts/setup_fuzz_host.sh --no-docker
```

설치 대상(기본):
- `rustup/cargo` (프로젝트 빌드)
- `clang` (libFuzzer 경로)
- `docker.io` (AFL++ Docker 경로, `--no-docker`로 제외 가능)
- `build-essential`, `pkg-config`
- `curl`, `git`, `jq`, `tmux`, `python3`, `python3-pip`

설치 후 확인:

```bash
docker --version
docker run --rm aflplusplus/aflplusplus afl-fuzz -h >/dev/null; echo "EC=$?"
clang++ --version
```

## 엔진 연결 예제 (ONNX)

아래 예제는 실행 경로를 확인하기 위한 것이다. 스모크 명령의 성공을 ONNX 로더 검증이나 퍼징 성과로 해석하지 않는다.

### AFL++ 실행 경로 스모크 (로더 검증 아님)
```bash
TOOL_AFLPP_CMD='docker run --rm -v "$PWD":/work -w /work aflplusplus/aflplusplus bash -lc "afl-fuzz -V 5 -i {corpus_dir} -o {run_dir}/afl-out -- /bin/true @@ >/dev/null 2>&1 || true"' \
cargo run --offline -- run --target onnx --backend aflpp --corpus-dir seeds/onnx --workers 2 --timeout-sec 30 --restart-limit 1
```

### AFL++ 도구 하네스 연결
```bash
TOOL_AFLPP_CMD='docker run --rm -v "$PWD":/work -w /work aflplusplus/aflplusplus bash -lc "afl-fuzz -n -V 5 -i {corpus_dir} -o {run_dir}/afl-out -- /work/target/debug/tool harness --target onnx --input @@ >/dev/null 2>&1 || true"' \
cargo run --offline -- run --target onnx --backend aflpp --corpus-dir seeds/onnx --workers 1 --timeout-sec 30 --restart-limit 1
```
`permission denied ... docker.sock`가 나오면 Docker 그룹 권한을 다시 적용(`newgrp docker`)하거나 새 셸에서 재시도한다.
이 예제는 `tool harness` 호출 경로를 보여준다. 실제 로더 실행 여부, 크래시와 커버리지는 해당 실행 로그로 확인해야 한다.

### libFuzzer 실행 경로 스모크 (로더 검증 아님)
```bash
TOOL_LIBFUZZER_CMD='clang++ --version >/dev/null' \
cargo run --offline -- run --target onnx --backend libfuzzer --corpus-dir seeds/onnx --workers 2 --timeout-sec 30 --restart-limit 1
```

### libFuzzer 도구 하네스 연결
```bash
scripts/build_libfuzzer_tool_driver.sh
TOOL_LIBFUZZER_CMD='TOOL_HARNESS_TOOL=./target/debug/tool TOOL_HARNESS_TARGET=onnx TOOL_HARNESS_EXT=onnx ./harnesses/libfuzzer/tool_harness_driver -max_total_time=5 {corpus_dir} >/dev/null 2>&1' \
cargo run --offline -- run --target onnx --backend libfuzzer --corpus-dir seeds/onnx --workers 1 --timeout-sec 30 --restart-limit 1
```
이 예제 역시 실제 로더 실행 여부와 결과를 로그로 확인해야 한다.

결과 확인:
```bash
LATEST=$(ls -dt data/runs/run-* | head -n 1)
cat "$LATEST/status.json"
ls -la "$LATEST/logs"
```

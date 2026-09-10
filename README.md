# Bug Bounty Fuzzing Platform (v2 Renewal)

> "퍼징으로 찾았다"에서 끝내지 않고, **재현·검증·리포트까지 자동화**하는 버그바운티용 퍼징 플랫폼.

## 먼저 읽기
- 설계/결정: [first.md](first.md)

## 기존 툴 대비 차별점 (Differentiators)
- **Deep & Structured Fuzzing**: 구조 인지형 mutator/harness로 얕은 파싱 에러가 아니라 깊은 경로의 메모리 오염을 겨냥한다.
- **Auto-Verification**: 동일 컨테이너에서 3회 재현 검증하고, 증거 번들/리포트를 자동 생성해 제출 품질을 보장한다.
- **Exploitability Triage**: ASan/Release 교차 검증과 스택/레지스터 분석으로 RCE 가능성을 등급화한다.
- **Reproducibility by Design**: 환경 고정/해시 기록으로 재현성을 강화한다.
- **LLM Assist (Out of Loop)**: 퍼징 루프 외부에서 Seed/Dictionary/Mutation guide를 보조한다.

### 목표 (Goals)
- 구조 인지형 mutator/harness로 더 깊은 경로를 타겟한다.
- 기존 툴 대비 재현 성공률/제출 승인률을 수치로 개선한다.
- 차별점 근거 지표 체크리스트는 내부 문서에서 관리한다.

## RCE 탐지 방법론 (요약)
- 핵심 본체는 **하네스/뮤테이터/triage**이며, 공개 방향은 [first.md](first.md)에 정리한다.
- **Format-Aware Mutator**: 헤더/메타/오프셋/길이 필드를 의도적으로 변조해 깊은 경로를 자극한다.
- **Targeted Harness**: mmap/텐서 디코딩/메모리 할당 경로를 직접 통과하도록 하네스를 설계한다.
- **Exploitability Triage**: 레지스터/스택/PC 오염 여부를 분석해 RCE 후보 등급을 부여한다.

## 핵심 목표
- 대상 포맷: **GGUF / ONNX / safetensors**
- 유효 버그 기준: **SEGV/Abort + 동일 입력 3회 재현 + 상위 3프레임 동일**
- 자동화 범위: **퍼징 실행 → 크래시 감지 → 재현 검증 → 리포트 초안 생성**

## 시스템 아키텍처
- Fuzz Manager: 컨테이너 실행/헬스/재시작 관리
- Job Queue: 파일 기반 작업 분배/상태 전이
- Artifact Store: 크래시/재현/증거 번들 저장

## 문서 가이드
- 공개 문서: [first.md](first.md)
- 퍼징컴 이관: [docs/fuzzing-pc-migration.md](docs/fuzzing-pc-migration.md)
- 그 외 운영 계획, 상세 명세, 실험 기록, 후속 계획은 내부 문서로 관리한다.

## CLI (확정)
- `tool run`, `tool triage`, `tool report`
- 결과 조회: `list`, `show <id>`, `export <id>`

## 변이 연산자 기본값 (`tool mutate`)

`--operator`를 주지 않으면 **크래시 헌팅 세트**가 돌아간다: 구조 인지 6종
(`shape`, `dtype`, `name`, `attribute`, `initializer_metadata`, `graph_metadata`)
**+ `aggressive`**. `aggressive`는 0 / -1 / `i32::MAX` / 거대값처럼 로더를 실제로 부수는 값을
꽂는 연산자다. 툴의 목적이 버그를 찾는 것이므로 기본이 이쪽이다.

- **실험을 재현할 때는 연산자를 반드시 명시할 것.** 포스터·논문의 "구조 인지 6-operator" 팔은
  위 6종만을 뜻한다. `scripts/coverage_experiment.py`(`STRUCTURE_AWARE`)와
  `scripts/run_onnx_abc_week.sh`(`MUTATE_OPERATORS`)는 이미 명시적으로 고정돼 있으므로,
  기본값이 바뀌어도 그 팔의 의미는 그대로다.
- 어떤 세트로 돌았는지는 `fuzz-loop` 로그와 캠페인 manifest의 `mutate_operators`에 남는다.

### GGUF 기본 세트 변경 (2026-08-30)

GGUF 기본 세트가 7종에서 **9종**으로 늘었다. 추가된 둘은 포맷 고유 결함에 도달하는 유일한
연산자이고, opt-in으로 남겨 두는 동안은 기본 캠페인이 그 결함을 찾을 수 없었다.

| | 연산자 |
|---|---|
| 변경 전(7종) | `header_counts`, `metadata_value`, `metadata_key`, `tensor_name`, `tensor_dtype`, `tensor_shape`, `tensor_offset` |
| 추가 | **`metadata_type`**(값 타입 재지정 — 같은 폭 유지 포함), **`kv_insert`**(시드에 없던 KV 삽입) |

- **2026-08-30 이전 GGUF 실험을 재현할 때는 위 7종을 `--operator`로 명시할 것.**
- 같은 날 변이 RNG의 출력 스크램블도 바뀌었다(`src/mutate/common.rs`). 시드가 같으면 여전히
  결정적이지만, **같은 시드가 이전과 같은 바이트를 만들지는 않는다** — 세 포맷 모두 해당한다.
  이전 LCG는 작은 수로 나눈 나머지가 균등하지 않았다(하위 비트가 교대, 연속 시드가 격자에
  놓임). 과거 코퍼스를 바이트 단위로 재현해야 하면 그때의 산출물을 쓸 것.
- 배치 변이는 이제 **아무 연산자도 처리하지 못한 시드를 이름으로 지목해 경고**한다
  (`WARN seed produced no mutants: ...`).

### GGUF 기본 세트 변경 (2026-09-03 · Stage E)

Stage E로 GGUF 뮤테이터가 ONNX급으로 넓어지면서 기본 세트가 **9종에서 12종**으로 늘었다.
추가된 셋은 GGUF 메타데이터의 대부분을 이루는 **배열**과 스칼라 경계값·유효 resize를 다룬다 —
이전 뮤테이터는 배열을 통째로 건너뛰어 배열 계열 결함(배열 arity, 거대 배열 할당)에 기본
캠페인이 닿지 못했다.

| | 연산자 |
|---|---|
| 변경 전(9종) | 위 7종 + `metadata_type`, `kv_insert` |
| 추가(3종) | **`array_mutate`**(배열 count 증폭·arity 강제·원소 변형, level 3), **`scalar_boundary`**(스칼라를 폭별 경계값으로, level 3), **`value_resize`**(문자열·배열 길이 유효 resize + 정렬 패딩 재계산, level 2) |
| 여전히 opt-in | **`havoc`**(포맷 무관 바이트 베이스라인 — 커버리지 비교 실험용이지 버그찾기가 아니다. ONNX와 동일하게 기본 제외) |

- **2026-09-03 이전 GGUF 실험을 재현할 때는 위 9종을 `--operator`로 명시할 것.**
- 매니페스트 `mutation_level`이 이제 연산자별로 기록된다(array_mutate·scalar_boundary=3,
  value_resize=2, 나머지=1) — ONNX와 같은 분류다.

## 기본 경로
- 데이터: `./data`
- 시드: `./seeds`

## 대시보드 (`tool ui-serve`)

```bash
cargo run --offline -- ui-serve --bind 127.0.0.1:8787
```

대시보드는 빌드 스크립트와 퍼징 루프를 띄우는 제어면이라 상태를 바꾸는 요청에는 인증이 필요하다.

- **토큰**: 서버가 시작할 때 32바이트 토큰을 만들어 `$XDG_RUNTIME_DIR/tool-ui-token`
  (없으면 `~/.cache/tool/ui-token`)에 `0600`으로 저장하고, 로그에는 **경로만** 찍는다.
  `/file?path=`가 데이터 디렉터리를 인증 없이 서빙하므로 토큰을 그 안에 두거나 stdout으로
  찍으면 그대로 노출된다. `TOOL_UI_TOKEN`으로 직접 지정할 수도 있다.
- **요청**: `POST /control/*`, `/replay/*`, `/target/*` 와 상태 파일을 다시 쓰는
  `GET /target/status`, `GET /target/build/status` 는 헤더 `X-Tool-Token: <토큰>` 이 필요하고,
  `Origin`/`Referer`가 있으면 대시보드 자신의 오리진이어야 한다. 브라우저는 페이지에 심긴
  토큰을 자동으로 붙이므로 대시보드 사용에는 달라지는 것이 없다.
  ```bash
  curl -X POST -H "X-Tool-Token: $(cat "$XDG_RUNTIME_DIR/tool-ui-token")" \
    'http://127.0.0.1:8787/control/start?target=onnx&backend=local-harness&duration_seconds=600'
  ```
- **Host**: 모든 경로에서 `Host` 헤더가 허용목록(바인드 호스트 · `127.0.0.1` · `localhost` ·
  `[::1]`, 각각 포트 유무)에 있어야 한다. DNS 리바인딩으로 되돌아온 페이지는 same-origin이 되어
  토큰까지 읽을 수 있으므로 `Origin`을 `Host`와 비교하는 것으로는 막을 수 없다.
- **와일드카드 바인드**: `--bind 0.0.0.0:...` 처럼 허용목록을 유도할 수 없는 주소는
  `TOOL_UI_ALLOWED_HOSTS=<host[:port],...>` 를 명시하지 않으면 시작을 거부한다(exit 8).
- **토큰 파일은 인스턴스별이 아니라 사용자별로 하나**다. 두 번째 `ui-serve`(포트가 달라도,
  `check_ui_routes.sh` 포함)를 띄우면 그 파일을 덮어쓴다. 살아 있는 서버의 실제 토큰은 언제든
  페이지에서 다시 꺼낼 수 있다: `curl -s http://127.0.0.1:8787/dashboard.html | grep 'id="ui-token"'`.
- **대시보드가 시작한 잡은 자기 세션에서 돈다**(정지 시 프로세스 그룹째 죽이기 위해 필요).
  따라서 `ui-serve`를 Ctrl-C 하거나 재시작해도 잡은 계속 돈다 — 상태 파일의 pid로 다시 인식되며,
  멈추려면 `/control/stop` 등을 쓴다. 24시간짜리 캠페인에는 이쪽이 맞는 동작이다.
- 재현 버튼은 경로 대신 `triage_id`를 보내고, 서버가 `data/triage/<id>/summary.json`에
  기록된 입력을 읽는다. `input=`으로 직접 지정하는 경로는 데이터/시드 디렉터리 안으로 제한된다.

점검: `scripts/check_ui_routes.sh`

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

### 파이썬 인터프리터 선택

ONNX/safetensors 라이브러리 프로브는 파이썬을 통해 실제 라이브러리를 부른다. 어느
인터프리터를 쓸지는 다음 순서로 정해진다.

1. `TOOL_PYTHON_BIN` (설정돼 있으면 그대로 사용)
2. 현재 작업 디렉터리의 `.venv/bin/python3`
3. 실행 중인 `tool` 바이너리 위쪽 3단계 안에서 찾은 프로젝트 루트(= `Cargo.toml`
   또는 `seeds/`가 있는 디렉터리)의 `.venv/bin/python3`
4. `python3`

3번이 있는 이유: 프로젝트 루트가 아닌 곳에서 `tool`을 실행해도(systemd 유닛, 캠페인
스크립트, run 디렉터리에서의 triage 재실행) venv를 계속 찾게 하기 위해서다. 관계없는
`.venv`를 잘못 집어오지 않도록 프로젝트 루트 표식이 함께 있을 때만 채택한다.
`TOOL_REQUIRE_LIBRARY_CONNECT=1`로 돌릴 때 이 선택이 틀리면 모든 입력이
harness-unavailable로 떨어지므로, 확실히 하려면 `TOOL_PYTHON_BIN`을 지정한다.

### 잡의 프로세스 그룹과 Ctrl-C

시간제한에 걸린 잡은 **하네스가 다시 띄운 손자 프로세스까지 함께** 종료된다(프로브가 실행한
파이썬 인터프리터, `llama-gguf-hash` 등). 예전에는 손자가 고아로 남아 며칠짜리 캠페인 동안
쌓였다. 누가 그 일을 하는지는 호스트에 coreutils `timeout`이 있느냐에 따라 다르다.

| 호스트 | 시간제한을 거는 주체 | 손자까지 죽나 |
|---|---|---|
| `timeout`(coreutils) 있음 — 보통의 리눅스 | `timeout`이 잡을 자기 프로세스 그룹에 띄우고 그룹째 시그널 | 예 (이전부터 그랬다) |
| `timeout` 없음 | `tool`이 자체 데드라인으로 잡을 자기 그룹에 띄우고 그룹째 시그널 | 예 (**R1에서 고친 부분**) |

두 경로 모두 대가가 같다: 잡이 터미널의 포그라운드 그룹 밖에 있으므로 **Ctrl-C는 `tool`에는
가지만 그 하네스에는 가지 않는다**. 대시보드가 띄운 잡도 같은 성질을 갖는다(R7). 캠페인은
systemd/nohup으로 도는 것이 정상 경로라 실사용에서는 문제가 되지 않지만, 손으로 돌리다 중단할
때는 `tool`이 끝난 뒤 남은 하네스가 있는지 확인하는 편이 좋다.

설치 후 확인:

```bash
docker --version
docker run --rm aflplusplus/aflplusplus afl-fuzz -h >/dev/null; echo "EC=$?"
clang++ --version
```

## 엔진 실환경 검증(ONNX 기준)

`tool run --backend <backend>`는 backend 1개만 선택해 실행한다. 장시간 비교/헌팅은 `tool campaign --mode <serial|parallel>`로 묶어 실행한다.

- `serial`: 같은 시드 스냅샷을 기준으로 backend를 순서대로 실행한다. 논문식 비교/재현성 기준에 적합하다.
- `parallel`: 같은 시드 스냅샷을 각 backend가 읽고, 결과는 backend별 data dir에 분리해 동시에 실행한다. 버그 헌팅 시간 단축 목적에 적합하다.

```bash
tool campaign --mode serial --target onnx --hours 168 --campaign-id paper-onnx-001
tool campaign --mode parallel --target onnx --hours 168 --campaign-id hunt-onnx-001
```

### `--timeout-sec`가 묶는 범위 (R3)

`--timeout-sec`는 **입력 하나를 처리하는 하네스 실행**의 벽시계 상한이다. 엔진 백엔드를
쓸 때 이것이 무엇을 묶고 무엇을 안 묶는지 헷갈리기 쉬워 명시한다.

| 경로 | `--timeout-sec`가 묶나 | 실제로 시간을 묶는 것 |
|---|---|---|
| `--backend local-harness` | **예** — 잡 1개마다 적용 | `--timeout-sec` |
| `--backend aflpp` / `libfuzzer` | **아니오** — 엔진 실행 시간에는 적용되지 않는다 | 엔진 자신의 옵션(AFL++ `-V`, libFuzzer `-max_total_time`). 래퍼가 `--duration-seconds`에서 계산해 넘긴다 |
| 백엔드가 찾아낸 크래시의 트리아지 | **예** — 재현 시도 1회마다 적용 | `--timeout-sec` |

설계상 의도된 동작이다. 엔진은 자기 루프를 스스로 관리하므로 바깥에서 한 번 더 묶으면
코퍼스를 저장하지 못한 채 죽는다. 다만 **엔진 백엔드 블록의 총 실행 시간을 줄이려면
`--timeout-sec`가 아니라 `--duration-seconds`(또는 캠페인의 `--block-seconds`)를 바꿔야 한다.**

엔진 명령 템플릿(`TOOL_AFLPP_CMD` / `TOOL_LIBFUZZER_CMD`)에는 `{timeout_sec}` 자리표시자가
있으므로, 입력 1개당 상한을 엔진에 직접 넘기고 싶다면 템플릿에 명시적으로 넣으면 된다
(예: libFuzzer `-timeout={timeout_sec}`). 넣지 않으면 엔진 기본값이 쓰인다.

짧은 스모크는 시간/입력 수를 제한한다.

```bash
make smoke TARGET=onnx
make smoke-all TARGET=onnx SECONDS=60
```

캠페인 결과는 `data/campaigns/<campaign-id>/` 아래에 저장된다. 원본 시드는 `seeds/<target>/`에서 캠페인 스냅샷으로 한 번 복사되고, backend별 실행은 `arms/<backend>/corpus/`와 `arms/<backend>/data/`로 분리된다. 같은 `campaign-id` 재사용은 결과 혼합을 막기 위해 차단한다. 중단 신호(`Ctrl+C`, `TERM`)를 받으면 실행 중인 backend 프로세스를 종료하고 `status.json`/`arms/<backend>/status.json`에 `interrupted` 상태를 기록한다.

**GGUF 엔진 비교의 초기 corpus 조건:** 실행 경로에 따라 선택하는 시드가 다르다.

| 실행 경로 | libFuzzer 초기 시드 출처 | AFL++ 초기 시드 출처 |
|---|---|---|
| `scripts/run_long.sh`에서 `--corpus-dir` 생략 / ops 루프 기본값 | 사용 가능한 `data/corpus/gguf-libfuzzer` 축소 fixture. 없거나 불완전하면 경고 후 `seeds/gguf`로 폴백 | `seeds/gguf` 원본 |
| `tool campaign` / `scripts/run_campaign.sh` (`serial`·`parallel`) | 공통 스냅샷의 팔별 사본 | 같은 스냅샷의 팔별 사본 |

축소 생성기 `scripts/build_gguf_libfuzzer_corpus.sh`의 기본 산출물 상한은 **1 MiB 미만**이다.
메타데이터 배열을 줄이고, 텐서는 크기에 맞는 오프셋 순 prefix를 유지하므로 원본과 내용이
달라질 수 있다. 기본 실행에서 축소본과 원본을 썼다면 비교 표·그림·논문·포스터에도 그 조건을
같이 적는다. 이는 엔진과 corpus 조건이 함께 다른 비교이며 엔진만의 효과로 해석할 수 없다.
campaign은 `--corpus-dir`로 선택한 출처(생략 시 `seeds/gguf`)를 한 번 복사하고 각 팔에
명시 경로로 전달하므로 libFuzzer만 자동 축소본으로 바꾸지 않는다. 동일 스냅샷은 초기 입력의
동일성을 뜻하며, 이후 발견물이나 엔진의 입력 길이·메모리 제한까지 같다는 뜻은 아니다.

비교 기록에는 작업 `corpus_dir`, 선택한 `seed_fixture`, campaign manifest의
`corpus_source`·`seed_snapshot`·`seed_snapshot_hash`와 실제 엔진 명령을 함께 보존한다.
`seed_fixture`는 경로 기록이며 내용 해시가 아니다. `null`이거나 과거 status에 필드가 없으면
출처를 추정하지 않는다. 과거 GGUF 결과에도 현재의 축소/원본 구분을 소급 적용하지 않으며,
같은 경로명만으로 당시 입력 바이트가 같았다고 주장하지 않는다.

퍼징컴에서는 먼저 `make build`, `make preflight TARGET=onnx`, `make smoke TARGET=onnx` 순서로 확인한다.

### AFL++
```bash
TOOL_AFLPP_CMD='docker run --rm {docker_user_flag} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc "afl-fuzz -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- /bin/true @@ >/dev/null 2>&1"' \
cargo run --offline -- run --target onnx --backend aflpp --corpus-dir seeds/onnx --workers 2 --timeout-sec 30 --restart-limit 1
```

### AFL++ (tool harness 연결)

`-n` black-box 모드에서 AFL++는 시그널로 죽은 실행만 크래시로 기록한다. `tool harness`는
라이브러리 크래시를 시그널이 아니라 **exit 4**로 보고하므로(입력 거부=9, 하네스 실행 불가=10),
`AFL_CRASH_EXITCODE=4`가 없으면 크래시가 아예 기록되지 않는다. 시드 코퍼스에 이미 크래시
입력이 있으면 dry-run이 전체 실행을 중단시키므로 `AFL_IGNORE_SEED_PROBLEMS=1`도 함께 준다.

```bash
TOOL_AFLPP_CMD='docker run --rm {docker_user_flag} {docker_hardening_flags} {docker_readonly_flags} -v {workdir_abs}:/work:ro -v {corpus_dir_abs}:/corpus:ro -v {run_dir_abs}:/out -w /work aflplusplus/aflplusplus bash -lc "AFL_CRASH_EXITCODE=4 AFL_IGNORE_SEED_PROBLEMS=1 afl-fuzz -n -V 5 -i {container_corpus_dir} -o {container_run_dir}/afl-out -- /work/target/debug/tool harness --target onnx --input @@ >/dev/null 2>&1"' \
cargo run --offline -- run --target onnx --backend aflpp --corpus-dir seeds/onnx --workers 1 --timeout-sec 30 --restart-limit 1
```
`permission denied ... docker.sock`가 나오면 Docker 그룹 권한을 다시 적용(`newgrp docker`)하거나 새 셸에서 재시도한다. `run --backend aflpp`는 `{docker_user_flag}`를 현재 사용자로 치환해 `afl-out`이 root 소유로 남지 않게 한다.

### libFuzzer (경로 스모크)
```bash
TOOL_LIBFUZZER_CMD='clang++ --version >/dev/null' \
cargo run --offline -- run --target onnx --backend libfuzzer --corpus-dir seeds/onnx --workers 2 --timeout-sec 30 --restart-limit 1
```

### libFuzzer (ONNX native harness 연결)
```bash
scripts/build_libfuzzer_onnx_native.sh
TOOL_LIBFUZZER_CMD='mkdir -p {artifact_dir} && LLVM_PROFILE_FILE={artifact_dir}/onnx-native-%p.profraw ./harnesses/libfuzzer/onnxruntime_loader_fuzzer -artifact_prefix={artifact_dir}/ -max_total_time=5 {corpus_dir} >/dev/null 2>&1' \
cargo run --offline -- run --target onnx --backend libfuzzer --corpus-dir seeds/onnx --workers 1 --timeout-sec 30 --restart-limit 1
```
기존 `build/cov*` ONNX Runtime에 링크하면 ORT를 직접 호출하고 native crash를 잡지만, ORT 내부 edge-guided libFuzzer coverage까지 보려면 sanitizer-coverage로 빌드한 ORT가 필요하다.

### libFuzzer (tool harness fallback)
```bash
scripts/build_libfuzzer_tool_driver.sh
TOOL_LIBFUZZER_CMD='mkdir -p {artifact_dir} && TOOL_HARNESS_TOOL=./target/debug/tool TOOL_HARNESS_TARGET=onnx TOOL_HARNESS_EXT=onnx ./harnesses/libfuzzer/tool_harness_driver -artifact_prefix={artifact_dir}/ -max_total_time=5 {corpus_dir} >/dev/null 2>&1' \
cargo run --offline -- run --target onnx --backend libfuzzer --corpus-dir seeds/onnx --workers 1 --timeout-sec 30 --restart-limit 1
```

결과 확인:
```bash
LATEST=$(ls -dt data/runs/run-* | head -n 1)
cat "$LATEST/status.json"
ls -la "$LATEST/logs"
```

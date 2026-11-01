> ## ⚠️ This is AI slop — use at your own risk
>
> Every line of this project was written by an AI agent (Claude) from conversational prompts. It has **not** been independently reviewed or security-audited by a human. Expect bugs, questionable design decisions, and possible security flaws.
>
> It deliberately runs an **uncensored (abliterated) local model** and feeds it **hostile malware samples**, so the blast radius if something is wrong is real. The sandboxing is best-effort, not a guarantee.
>
> **No warranty of any kind. Provided as-is.** Run it only inside an isolated, disposable VM; read the code before you trust it; and never point it at anything — a machine, a network, a sample — you can't afford to lose or contain. If that's not acceptable to you, don't run it.

# re-lab

A local reverse-engineering workbench. A language model you run yourself works through headless Ghidra to answer questions about binaries. Each piece runs in its own sandbox, so neither the model nor Ghidra can reach the network or the rest of your machine.

```
 you ── agent (one Python file) ─────┬── model server   llama.cpp + GGUF model
                                     │     macOS : native Metal GPU, macOS sandbox, 127.0.0.1 only
                                     │     Linux : CUDA/CPU container, no network, Unix socket only
                                     │
                                     └── Ghidra MCP     Ghidra 12.1.4 + pyghidra-mcp in a container
                                           no network, read-only root, samples mounted read-only
```

How the work is split:
- **Ghidra does the analysis:** disassembly, decompilation, strings, imports, cross-references.
- **The model reasons about it:** it reads Ghidra's results, decides what to look at next, and writes the answer.
- **The agent connects them:** it passes the model's tool requests to Ghidra and refuses anything not on an allowlist.

Default model: [`mlabonne/Daredevil-8B-abliterated`](https://huggingface.co/mlabonne/Daredevil-8B-abliterated), Q8_0 build from `mlabonne/Daredevil-8B-abliterated-GGUF`. Any GGUF model can replace it (see *Changing the model*).

**Contents:** [Platforms](#platforms) · [Requirements](#requirements) · [Setup](#setup) · [First session](#first-session-walkthrough) · [New samples](#starting-on-new-samples) · [Agent reference](#agent-reference) · [Tools](#ghidra-tools) · [make targets](#make-targets) · [Configuration](#configuration) · [Logs](#logs) · [Isolation](#what-is-isolated-and-how) · [Security testing](#security-testing) · [Changing the model](#changing-the-model) · [Updating pins](#updating-pins) · [Packaging](#packaging-the-lab) · [Troubleshooting](#troubleshooting) · [Test status](#test-status)

---

## Platforms

| Host | Model runs on | Model-server isolation |
|---|---|---|
| macOS, Apple Silicon | GPU via Metal, natively | macOS Seatbelt profile (`sandbox/llama-server.sb`) |
| Linux + NVIDIA GPU | GPU via CUDA, in a container | `--network none` container, reachable only through a Unix socket |
| Linux, no GPU | CPU, same container | same as above (slow; fine for trying things out) |

`LLAMA_BACKEND="auto"` in `config.env` picks the row for you. The Ghidra container is the same on every platform.

> **Keep the lab out of synced folders** (Nextcloud, Dropbox, iCloud Drive, OneDrive). Anything in `samples/` would be uploaded and copied to your other devices. `models/` holds an 8 GB file, and Ghidra's lock files in `projects/` cause sync conflicts. If you must keep the code in a synced folder, exclude `samples/`, `models/`, `projects/`, `logs/`, `vendor/` and `.run/` from syncing.

## Requirements

Everyone: `git`, `curl`, `make`, Docker, and about 25 GB of free disk (model ~8.5 GB, Ghidra image ~2.5 GB, llama.cpp build ~1 GB).

**macOS (Apple Silicon)**
- Xcode Command Line Tools: `xcode-select --install`
- `brew install cmake uv` (`uv` is optional; it supplies a Python 3.12 for the agent)
- Docker Desktop or OrbStack, running. In Docker Desktop, give the VM at least 12 GB of memory (Settings → Resources), or lower `GHIDRA_MEM` in `config.env`.

**Linux + NVIDIA**
- NVIDIA driver 570 or newer (the image uses CUDA 12.8; set `CUDA_VERSION` for older drivers)
- Docker Engine and the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html), then `sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker`
- Python 3.10+ or `uv`
- VRAM: the default Q8_0 model needs about 10 GB. On an 8 GB card set `MODEL_QUANTS="Q4_K_M"` before `make model`.
- Optional, for a much faster build: set `CUDA_ARCHS` to your card only (`86` RTX 30xx, `89` RTX 40xx, `120` RTX 50xx).

## Setup

Run everything from the lab folder. Adding `2>&1 | tee logs/<name>.log` to a step keeps its output for later.

```bash
make setup     # checks prerequisites, creates folders, builds the agent's Python environment
make llama     # macOS: compiles llama-server with Metal (~3 min). Linux: builds the CUDA/CPU image
make model     # downloads the model (8.1 GiB) and checks it against Hugging Face's SHA-256
make ghidra    # builds the Ghidra image; on arm64 this also compiles Ghidra's decompiler
make model-up  # starts the model server in its sandbox, in the background
make smoke     # sends the model one short request
```

The network is needed only for `setup`, `llama`, `model` and `ghidra`. Nothing in the running stack uses it.

`make setup` ends with this when everything is in place:

```
==> OS: Darwin arm64, model backend: metal
 ok  git
 ok  curl
 ok  docker
 ok  cmake
 ok  Xcode Command Line Tools
 ok  sandbox-exec
 ok  docker daemon reachable
 ok  folders: samples/ projects/ logs/ models/ .run/
==> Installing hash-pinned agent packages
 ok  agent environment: agent/.venv
 ok  setup complete. Next: make llama model ghidra
```

`make smoke` on an M3 Max:

```
reply:    Life is full of surprises.
finished: on its own (good)
speed:    42.5 tokens/s generating, 75.5 tokens/s reading the prompt
```

Check the output:
- `finished: hit the token limit` usually means the wrong chat template (see *Changing the model*).
- Single-digit speeds on a Mac mean the model isn't using the GPU.

`make model-info` describes the model file itself:

```
file:          daredevil-8b-abliterated.Q8_0.gguf (GGUF v3)
name:          Daredevil-8B-abliterated  arch: llama
trained ctx:   8192
bos token:     128000 '<|begin_of_text|>'
eos token:     128001 '<|end_of_text|>'
has token:     <|eot_id|>
chat template: NONE embedded (set LLAMA_CHAT_TEMPLATE in config.env)
```

This file has no chat template of its own, so the lab supplies `templates/llama3.jinja` (the setting is already made in `config.env`).

## First session walkthrough

A **sample** is the program file you want to analyse: a `.exe`, `.dll`, Linux ELF, Mac executable, firmware image and so on. The lab never runs it. Ghidra only reads and disassembles it.

For a harmless first test, use the system's own `ls`. On a Mac it contains both Intel and Apple Silicon code, so extract just the Apple Silicon part:

```bash
lipo -thin arm64e /bin/ls -output samples/ls    # macOS
cp /bin/ls samples/ls                           # Linux
make agent
```

On the first run with a new sample, Ghidra imports it, analyses it and builds a search index; for `ls` this takes a few minutes. A progress line shows which stage it is in. Later sessions reuse the saved project and start in about a minute. Startup looks like this:

```
model: daredevil-8b-abliterated.Q8_0, context 8192 tokens, via http://127.0.0.1:8080
log:   logs/session-20261031-161934.jsonl  (Ghidra output: logs/ghidra-20261031-161934.log)
Starting Ghidra in its container (importing new samples can take a while) ...
binaries: /ls-ff815f
tools:    12 allowed (read-only), mode json
Ready. /help for commands.
re-lab>
```

Ghidra gives each binary a project name (`/ls-ff815f` here). The agent fills that name in for you while there is only one binary.

### Commands you can type

Everything below is real output from that session.

```
re-lab> /bins
  /ls-ff815f  [analysis_complete, code_indexed, strings_indexed]

re-lab> /call list_imports {"limit": 8}
imports:
  - name: ___assert_rtn
    library: /usr/lib/libSystem.B.dylib
  - name: ___error
    library: /usr/lib/libSystem.B.dylib
  ...

re-lab> /call search_strings {"query": "usage", "limit": 3}
strings:
  - value: |
      usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]
    address: 100004e06
    similarity: 1.0

re-lab> /decompile entry
name: entry-100000960
code: |
  void entry(undefined8 param_1,long param_2)
  {
    ...
    _setlocale(0,"");
    BVar6 = _compat_mode("bin/ls","Unix2003");
    DAT_10000c024 = (char)BVar6;
    iVar7 = _isatty(1);
    if (iVar7 == 0) {
      DAT_10000c0d0 = 1;
      pcVar12 = _getenv("COLUMNS");
    ...
    iVar7 = _getopt_long(param_1,param_2,"+@1ABCD:FGHILOPRSTUWXabcdefghiklmnopqrstuvwxy%,",
                         &PTR_s_color_100008000,0);
    ...
```

### Asking the model

The default Daredevil model is an 8B Llama 3 merge with an 8K context, and it was not trained for tool use. The surest way to get a thorough answer is to hand the model the code first, rather than relying on it to fetch everything itself.

**Deep-dive on a function and everything it calls: `/explain`.** This is the command to reach for when you want to understand what a function actually does. It decompiles the function *and the functions it calls* (two levels deep by default), then asks the model to walk through the whole flow in order — what each child function does, which strings and constants it checks, and what the function is for. This is what fixes the usual problem of the model describing one function and only guessing about the ones it calls.

```
re-lab> /explain FUN_00401b36
gathering FUN_00401b36 and the functions it calls (depth 2) ...
  decompiled 9: FUN_00401b36, FUN_00401060, FUN_004010b5, FUN_00401204, FUN_00401664, FUN_00401336, FUN_004018ec, FUN_00401000, FUN_004011a0
  . <the model walks through the prompt/read loop, the name check, the serial parse and the comparison>
...
```

Give it a plain name or an address, an optional depth (`/explain entry 3`), and a binary name only if the project has more than one (`/explain entry 2 /level1.exe-4abf2f`). Depth 2 reaches a function's grandchildren, which is usually where the real logic sits — in `level1.exe`, `entry` calls an init routine that calls the actual password checker, so `/explain entry` gets to it while `/decompile entry` alone would not. The gathered bundle is capped (10 functions, ~9,000 characters) so it fits the context; the `decompiled N:` line tells you exactly which functions the model was given.

**You choose one function, it explains: this works well too.** Anything you run with `/decompile` or `/call` becomes part of the conversation, so you can ask about it right after. Real output:

```
re-lab> /decompile FUN_1000042ec
name: FUN_1000042ec-1000042ec
code: |
  void FUN_1000042ec(void)

  {
    _fprintf(*(FILE **)PTR____stderrp_100008518,
             "usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]\n"
            );
                      /* WARNING: Subroutine does not return */
    _exit(1);
  }
signature: void FUN_1000042ec(void);
callees: [_exit, _fprintf]
referenced_strings: ["usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]\n"]
re-lab> Explain the code above. What does this function do, and why would entry call it?
  . This function prints an error message and exits the program with code 1.

This function is likely the error handling code for the ls command, and it would be called by the entry point when the user provides invalid arguments or options.
```

That is correct: it is `ls`'s usage function. It answered in one step without calling any tools.

**It investigates on its own: this works, but shallowly.** Each step prints the model's reasoning (`.`), the tool call (`->`) and the size of the result (`<-`). Real output, shortened in the middle:

```
$ make agent ARGS="--once 'Decompile entry and explain step by step what it does.'"
  . Decompile the entry point to understand the sample's initial actions.
  -> decompile_function({"binary_name": "/ls-ff815f", "name_or_address": "entry", "include_callees": true, "include_strings": true, "include_xrefs": true})
  <- 14,389 chars in 0.6s
  . The entry function initializes various variables, checks for command-line options, and sets up the program's behavior.
  -> decompile_function({"binary_name": "/ls-ff815f", "name_or_address": "entry-100000960", ...})
  <- 194 chars in 0.0s
  ...
  -> decompile_function({"binary_name": "/ls-ff815f", "name_or_address": "FUN_100002528", ...})
  <- 1,537 chars in 0.0s
  . The function FUN_100002528 checks some conditions and then calls other functions based on those conditions.
  -> list_exports({"binary_name": "/ls-ff815f", "query": ".*", "offset": 0, "limit": 25})
  <- 236 chars in 0.0s

The binary is a Mach-O executable that exports the Mach-O header, the execute header, and the entry function, and contains functions that set up the program's behavior based on command-line options and environment variables.
```

It went to `entry` straight away, but the summary stays vague, and it spent steps on a wrong function name and on exports. Whole-program questions like this are where a small model runs out of room. The decompiled `entry` is 14,389 characters, and to fit the 8K-token context the agent shows the model only the first 6,000 characters of any one result (`AGENT_MAX_RESULT_CHARS`). For better results:
- Use `/functions` first to get a one-line summary of every function — a map of the binary that tells you which ones are worth a closer look.
- Use `/explain NAME` to analyse a function together with the functions it calls — the deep-dive path once you've spotted something.
- Or use `/decompile` on one function, then ask about it.
- Ask narrow questions that name a function or address.
- Use a stronger model (see *Changing the model*) — this is the single biggest improvement for the quality and depth of the explanations.

### Leaving

`/quit` (or Ctrl-D) saves the Ghidra project and stops its container. Ctrl-C interrupts the current question without leaving.

## Starting on new samples

A Ghidra project keeps every binary it has imported. Deleting a file from `samples/` doesn't remove it from the project, and the model sees all of a project's binaries. So use one project per case:

```bash
make status                          # no re-lab-ghidra container should be running
rm samples/ls                        # clear out the previous case (README.txt can stay)
cp /path/to/new/files/* samples/     # add the new samples
make agent ARGS="--project case2"    # a new project imports everything now in samples/
```

The first start of a new project imports, analyses and indexes its samples, which takes a few minutes. Later starts are quick. Project names may contain letters, digits, `.`, `_` and `-`. To go back to an earlier case, use its name: `make agent ARGS="--project lab"`. To make a project the default for plain `make agent`, set `GHIDRA_PROJECT="case2"` in `config.env`.

`make projects` lists the projects and the samples each one imported:

```
doccheck  3.2M
    ls  sha256 6d6d5c1cf1ab...
lab  6.9M  (default, GHIDRA_PROJECT)
    ls  sha256 6d6d5c1cf1ab...
```

`make delete-project NAME=doccheck` deletes a project: its Ghidra database, its search index and its import record. It lists what it will remove and asks first. It refuses while that project is open in a running session, and it never touches `samples/`. Output from a test project:

```
==> This deletes project 'old1':
    projects/old1.gpr  (0)
    projects/old1.rep  (204K)
    projects/old1.lock  (0)
    projects/old1-pyghidra-mcp  (8.0K)
    projects/old1.re-lab-imported  (4.0K)
Delete? [y/N] y
 ok  deleted project 'old1'
```

Two things to keep in mind:
- **`samples/` is shared by all projects.** A new project imports whatever is in it at its first start, so empty it before you start the next case.
- **Don't replace a sample inside an existing project.** Samples are tracked by content, not by file name, so a changed file is imported again, next to the old version. Start a new project instead.

## Agent reference

Start it with `make agent`, adding options through `ARGS`:

```bash
make agent                                      # interactive, read-only tools
make agent ARGS="--allow-edits"                 # also let the model rename, retype and comment
make agent ARGS="--once 'Decompile entry and explain what it does.'"   # one question, then exit
make agent ARGS="--help"                        # all options
```

| Option | Default | Meaning |
|---|---|---|
| `--once QUESTION` | | answer one question and exit |
| `--project NAME` | `lab` | Ghidra project under `projects/` |
| `--allow-edits` | off | adds the annotation tools (see below). Samples are never modified. |
| `--mode json\|native` | `json` | `json`: grammar-constrained steps, works with any model. `native`: OpenAI tool calls, for models trained on them |
| `--max-steps N` | 15 | tool calls per question before the model must answer |
| `--max-result-chars N` | 6000 | how much of each tool result the model sees (logs always keep it all) |
| `--temperature T` | 0.2 | sampling temperature |
| `--max-tokens N` | 1024 | longest single model reply |
| `--tool-timeout S` | 300 | seconds before a Ghidra call is abandoned |
| `--analysis-timeout S` | 1800 | how long to wait at startup for analysis and indexing |
| `--no-wait` | off | don't wait for analysis/indexing. Decompile calls may then time out until indexing finishes |

Commands at the `re-lab>` prompt:

| Command | What it does |
|---|---|
| `/help` | list these commands |
| `/bins` | binaries in the project, with analysis and index status |
| `/tools` | tools the model may call, and the ones hidden from it |
| `/call TOOL {json}` | run a Ghidra tool yourself. `binary_name` is filled in when there is one binary, and the allowlist applies. The result also goes into the conversation, so you can ask about it next. |
| `/decompile NAME [BINARY]` | `decompile_function` with callees and strings; ask about the result next |
| `/explain NAME [DEPTH] [BINARY]` | decompile NAME **and the functions it calls** (DEPTH levels, default 2), then have the model walk through the whole flow in depth. The deep-dive command — use it when you want to understand what a function does, not just see its code. |
| `/functions [LIMIT] [BINARY]` | list the binary's own functions (imports and library thunks excluded), each with a 1–2 sentence summary of what it does. Summaries are generated one function at a time and printed as they come, so you can watch progress and Ctrl-C to stop. `LIMIT` caps how many are summarised (default 50); pass a bigger number, e.g. `/functions 200`, to cover them all. A map of the whole binary before you dive into any one function. |
| `/prompt` | the exact system prompt the model receives (edit it in `agent/system_prompt.md`) |
| `/template` | the chat template the model server is using |
| `/reset` | forget the conversation, keep the Ghidra session |
| `/log` | path of this session's log |
| `/quit`, `/exit`, `/q` | save the project and exit |

You can also feed commands from a file or a pipe. This is how the examples above were recorded:

```bash
printf '%s\n' '/bins' '/call list_imports {"limit": 8}' '/decompile entry' '/quit' | make agent
```

## Ghidra tools

The agent allows only these. `binary_name` is required everywhere except `list_project_binaries`, and `/call` fills it in when there is one binary. Every example below was run against the `ls` sample on an M3 Max and worked as shown.

**Read-only (always available)**

| Tool | Example |
|---|---|
| `list_project_binaries` | `/call list_project_binaries {}` |
| `list_project_binary_metadata` | `/call list_project_binary_metadata {}` |
| `decompile_function` | `/call decompile_function {"name_or_address": "entry", "include_callees": true}` (also takes an address like `"0x100000960"`, or a list) |
| `disassemble` | `/call disassemble {"address": "0x100000960", "count": 10}` (an address, not a name) |
| `search_symbols_by_name` | `/call search_symbols_by_name {"query": "getenv", "limit": 5}` (regex) |
| `search_strings` | `/call search_strings {"query": "usage", "limit": 3}` (plain text, not regex) |
| `search_code` | `/call search_code {"query": "getenv", "search_mode": "literal", "limit": 2, "include_full_code": false}`; `"search_mode": "semantic"` finds similar code by meaning |
| `list_imports` | `/call list_imports {"query": "getenv"}` (regex; default limit 25) |
| `list_exports` | `/call list_exports {"limit": 10}` |
| `list_xrefs` | `/call list_xrefs {"name_or_address": "_getenv"}` |
| `read_bytes` | `/call read_bytes {"address": "0x100000960", "size": 16}` |
| `gen_callgraph` | `/call gen_callgraph {"function_name": "entry"}` (Mermaid diagram text) |

**Annotation (only with `--allow-edits`)**

These change the Ghidra project only, never the sample file.

| Tool | Example |
|---|---|
| `rename_function` | `/call rename_function {"name_or_address": "FUN_100002564", "new_name": "renamed_by_me"}` |
| `rename_variable` | `/call rename_variable {"function_name_or_address": "entry", "variable_name": "argc", "new_name": "arg_count"}` (see below) |
| `set_variable_type` | `/call set_variable_type {"function_name_or_address": "entry", "variable_name": "argv", "type_name": "char **"}` (see below) |
| `set_function_prototype` | `/call set_function_prototype {"function_name_or_address": "FUN_1000042ec", "prototype": "void FUN_1000042ec(void)"}` (the prototype includes the name; a different name renames the function) |
| `set_comment` | `/call set_comment {"target": "entry", "comment": "argument parsing starts here", "comment_type": "plate"}` |

**Editing variables.** `rename_variable` and `set_variable_type` only see variables Ghidra has saved for a function. The names in decompiled code (`param_1`, `iVar11`, `pcVar12`) are generated for display and aren't saved until the function has a real signature, so using them fails with *Variable 'param_1' not found in function 'entry'*. Set the prototype first, then use its parameter names. Real output:

```
re-lab> /call set_function_prototype {"function_name_or_address": "entry", "prototype": "void entry(int argc, char **argv)"}
old_prototype: undefined entry(void)
new_prototype: void entry(int argc, char * * argv)
re-lab> /call rename_variable {"function_name_or_address": "entry", "variable_name": "argc", "new_name": "arg_count"}
variable_kind: parameter
old_name: argc
new_name: arg_count
re-lab> /call decompile_function {"name_or_address": "entry"}
signature: void entry(int arg_count,char **argv);
```

Output trimmed to the relevant fields. The decompiler then adds a harmless *Unknown calling convention* warning, because the prototype doesn't name one. With `--allow-edits`, the model's instructions include this rule too.

Never offered to the model: `delete_project_binary`, `import_binary`, and any tool a future pyghidra-mcp adds. The agent calls `save` itself when you quit.

Each sample is imported into a project once, keyed by its SHA-256, so renaming a file doesn't re-import it. To work on a new set of samples, see *Starting on new samples*.

## make targets

| Target | What it does |
|---|---|
| `make help` | list targets |
| `make setup` | check prerequisites, create folders, build the agent environment |
| `make llama` | build llama-server for the active backend |
| `make model` | download the pinned model and verify it (re-verifies if already present) |
| `make ghidra` | build the Ghidra + pyghidra-mcp image |
| `make all` | `setup`, `llama`, `model`, `ghidra` in order |
| `make model-up` / `make model-down` | start / stop the model server in the background |
| `make model-fg` | run the model server in this terminal (to watch its log) |
| `make smoke` | one short request: reply, how it ended, speed |
| `make model-info` | the model file's tokens and whether it embeds a chat template |
| `make template` | the chat template the running server uses |
| `make status` | backend, whether the model is up, running lab containers |
| `make profile` | the resolved macOS sandbox profile |
| `make agent` | the agent (`ARGS="..."` for options) |
| `make projects` | list Ghidra projects and the samples each imported |
| `make delete-project NAME=…` | delete a project (asks first; samples are not touched) |
| `make package` | `dist/re-lab-<date>.tar.gz` with only the files needed to run the lab |
| `make security` | run the security gate (supply-chain + fuzz); same checks as the pre-commit hook |
| `make hooks` | install the git pre-commit hook so the gate runs on every commit |
| `make clean-run` | stop the model and delete `.run/`; models, projects and logs stay |

## Configuration

Everything lives in `config.env`. After a change, re-run the matching step.

| Setting | Default | Notes |
|---|---|---|
| `LLAMA_BACKEND` | `auto` | `metal`, `cuda`, `cpu`, or `auto` |
| `LLAMA_CPP_TAG`, `LLAMA_CPP_COMMIT` | `b11600`, `ace20f6…` | pinned llama.cpp; the commit is checked after cloning → `make llama` |
| `LLAMA_HOST`, `LLAMA_PORT` | `127.0.0.1`, `8080` | macOS only. Never use `0.0.0.0`. |
| `LLAMA_CTX` | `8192` | context size (Llama 3 8B was trained on 8K) |
| `LLAMA_EXTRA_ARGS` | | extra llama-server flags, e.g. `--threads 8` |
| `LLAMA_CHAT_TEMPLATE` | `templates/llama3.jinja` | must be inside `templates/`; `""` uses the model's embedded template |
| `LLAMA_IMAGE`, `CUDA_VERSION`, `CUDA_ARCHS`, `LLAMA_GPUS` | | Linux container settings → `make llama` |
| `MODEL_REPO`, `MODEL_REVISION`, `MODEL_QUANTS` | Daredevil GGUF, `main`, `Q8_0 Q6_K Q5_K_M Q4_K_M` | first quant found is used → `make model` |
| `GHIDRA_VERSION`, `GHIDRA_DATE`, `GHIDRA_SHA256` | 12.1.4 | pinned Ghidra release → `make ghidra` |
| `PYGHIDRA_MCP_VERSION` | `0.2.7` | must match `ghidra/requirements.lock` |
| `GHIDRA_MEM`, `GHIDRA_HEAP`, `GHIDRA_CPUS` | `12g`, `8g`, `8` | container limits; CPUs are capped at what Docker has |
| `GHIDRA_PROJECT` | `lab` | default project for `make agent` |
| `GHIDRA_SYMBOLS` | `off` | `local` uses PDB files you put in `symbols/` |
| `AGENT_TOOL_MODE`, `AGENT_MAX_STEPS`, `AGENT_MAX_RESULT_CHARS`, `AGENT_TEMPERATURE` | `json`, `15`, `6000`, `0.2` | defaults for the agent options above |

## Logs

| File | Contents |
|---|---|
| `logs/session-<time>.jsonl` | one JSON record per event: question, each model step (with token usage), each tool call with its **full** result, the answer |
| `logs/ghidra-<time>.log` | Ghidra / pyghidra-mcp output for that session |
| `logs/llama-server.log` | model server output (macOS); on Linux use `docker logs re-lab-llama` |

To replay the latest session as text (or name one file instead of the `*`):

```bash
python3 - logs/session-*.jsonl <<'EOF'
import json, sys
for r in map(json.loads, open(sys.argv[-1])):
    if r["kind"] == "question": print("Q:", r["text"])
    elif r["kind"] == "tool":   print("  ", r["tool"], json.dumps(r["args"]), len(r["result"]), "chars")
    elif r["kind"] == "answer": print("A:", r["text"])
EOF
```

## What is isolated, and how

**Model server, macOS.** `llama-server` is compiled from a pinned llama.cpp commit, without its HTTPS client and without the web UI download. It starts with an empty environment under `sandbox-exec` and `sandbox/llama-server.sb`. The profile:
- denies all network operations except listening on `127.0.0.1:8080`
- blocks the system services that resolve DNS or fetch URLs on a process's behalf
- refuses to start any other program
- denies reads in your home folder except the model, the chat template, the binary and its API key
- denies writes outside temporary folders

`make profile` prints it. On an M3 Max the server runs at full GPU speed under this profile, with no sandbox denials logged for it.

**Model server, Linux.** The same pinned llama.cpp, built in `llama/Dockerfile`, runs with `--network none`, a read-only root filesystem, all capabilities dropped, `no-new-privileges` and your uid. It sees only the model folder, the templates folder and its key (all read-only), plus the folder holding its Unix socket.

**Ghidra.** pyghidra-mcp 0.2.7 and Ghidra 12.1.4 run in a container started by `scripts/ghidra-mcp.sh`:
- `--network none`, read-only root, no capabilities, your uid, memory/CPU/process limits
- `samples/` mounted read-only, `projects/` read-write, nothing else from the host
- MCP over stdin/stdout, so there is no listening port
- PDB symbol-server lookups off by default (`GHIDRA_SYMBOLS`); otherwise pyghidra-mcp would configure Microsoft's public symbol server

**Agent.** `agent/agent.py`:
- its only connections are to the model server (loopback TCP or Unix socket) and to the Ghidra wrapper; proxy environment variables are ignored
- it exposes only the allowlisted tools above and uses model output only as tool arguments, never executing it
- it logs everything

**Supply chain.**
- llama.cpp: pinned tag, commit checked after cloning
- Ghidra: release zip checked against the SHA-256 in its release notes
- Python packages: all hash-locked, wheels only
- model: pinned to a Hugging Face commit and checked against the SHA-256 Hugging Face publishes; re-hashed whenever the file changes

**What the isolation does not cover.**
- An abliterated model will follow instructions planted in a sample's strings or symbols. The agent marks tool output as untrusted, but the real protection is that the model can do nothing beyond the allowlisted Ghidra tools.
- Ghidra parses hostile files. The container limits what a parser exploit could reach, but it shares a kernel with the Docker VM (on macOS) or the host (on Linux). For high-risk samples, run the whole lab inside a dedicated VM.
- Nothing here executes samples. Dynamic analysis needs its own, separate setup.

## Security testing

Because this lab pulls third-party packages and feeds the model hostile input, two security checks run on **every commit** — locally through a git pre-commit hook and again in GitHub Actions on every push and pull request. Same script both places (`scripts/security-check.sh`), so nothing lands without passing it.

Enable the local hook once per clone:

```
make hooks          # git config core.hooksPath .githooks
make security       # run the gate by hand any time
```

What it checks:

- **Supply chain — prevent malicious packages** (`scripts/check_deps.py`). Every dependency in `agent/requirements.lock` and `ghidra/requirements.lock` must be pinned with a `sha256` hash and come from the package index (no `git+`, URL, or editable sources, which would run arbitrary code at install time). Installs must use `--require-hashes --only-binary=:all:`, so pip refuses an unhashed or source-only package and never runs a `setup.py`. The three large downloads (Ghidra, llama.cpp, the model) must each keep their integrity check — the Ghidra zip's `sha256`, llama.cpp's pinned commit, the model's Hugging Face hash. And no script may pipe a download into a shell. CI additionally runs **`pip-audit`** against both locks to flag packages with known published vulnerabilities (needs network, so it's CI-only; `SECURITY_PIP_AUDIT=1 make security` runs it locally).
- **Fuzzing — the untrusted-input parsers** (`tests/fuzz_agent.py`). The agent reads two attacker-influenced streams: Ghidra results whose strings and symbols come from the sample (written by malware authors), and the model's raw output. The fuzzer throws thousands of malformed, hostile, and oversized inputs at the functions that parse and render those streams and asserts each one never raises, never hangs (a watchdog interrupts any call over 3s), and never amplifies its input. It imports only the standard library and needs no model or Ghidra, so it runs in about a second. The pre-commit hook runs ~2,000 cases; CI runs ~40,000.

Neither check needs the model, Ghidra, Docker, or the network (except CI's `pip-audit`), so the gate is fast and runs anywhere with `python3`. A failure prints exactly what broke and blocks the commit; `git commit --no-verify` bypasses it for a genuine emergency.

## Changing the model

A model trained for tool use with a longer context will do much better with this stack than an 8B Llama 3 merge. The 8B is what makes answers shallow and self-contradictory; a larger model is the single biggest improvement you can make.

**Recommended for a 48 GB M3 Max: a 30B-class mixture-of-experts coder model**, for example `Qwen3-Coder-30B-A3B-Instruct`. It has ~30B parameters but only ~3B active per token, so on an M3 Max it runs about as fast as the 8B while reasoning far better, and it is strong at both code and following a tool protocol. It fits comfortably at Q4_K_M (~18 GB) or Q5/Q6 (~23–26 GB), leaving room for a large context.

**Abliterated vs. stock, and what "safe" actually means here.** The default `Daredevil-8B-abliterated` is an *abliterated* model: its built-in refusals have been stripped so it never balks at analysing a malware sample or writing a keygen. That is a capability choice, not a safety one — abliteration removes refusals, so an abliterated model is if anything *more* willing to follow any instruction, including text planted in a sample. What makes this lab safe to point at hostile code is not the model but the two model-independent guarantees around it:

- **Isolation.** llama-server runs with no outbound network at all — a macOS Seatbelt profile that denies all networking except binding `localhost`, plus DNS and the network daemons, and forbids launching other programs or reading your home folder (`sandbox/llama-server.sb`); on Linux, a `--network none` container. The agent only exposes the read-only Ghidra tools. Even a fully uncensored model physically cannot phone home or act outside Ghidra. This is identical for every model you load.
- **Integrity.** `get-model.sh` records the file's SHA-256 in `models/MODEL.lock`, and `start-model.sh` refuses to start unless the file still matches, so you always run the exact bytes you verified.

So if you want to stay abliterated at 30B (recommended, to match the current setup and never hit a refusal), point `MODEL_REPO` at an abliterated GGUF of the model — community abliterations of Qwen3-Coder-30B are published on Hugging Face by the usual groups (e.g. `huihui-ai`, `mlabonne`). Pull from the publisher's own repo, not a random mirror; the first download is trust-on-first-use, then the hash pin takes over. The stock `Qwen3-Coder-30B-A3B-Instruct-GGUF` is a fine fallback — standard coder models rarely refuse RE work — but the abliterated build removes the question entirely.

```
# in config.env
MODEL_REPO="mradermacher/Huihui-Qwen3-Coder-30B-A3B-Instruct-abliterated-i1-GGUF"
MODEL_QUANTS="Q4_K_M Q5_K_M"                              # first one found is used; make model prints and pins what it picked
LLAMA_CHAT_TEMPLATE=""                                    # Qwen embeds its own template; confirm with make model-info
LLAMA_CTX="32768"                                         # raise now that the model supports it
```

This is huihui-ai's abliterated Qwen3-Coder-30B, quantised by mradermacher with an importance matrix (`i1`). **Fit on a 48 GB M3 Max:** `i1-Q4_K_M` (~18.6 GB) is the sweet spot — it runs beside the 12 GB Ghidra container and macOS with headroom. `i1-Q5_K_M` (~21.7 GB) also fits if you lower the Docker Desktop VM memory (these samples don't need 12 GB of Ghidra); `i1-Q6_K` (~25 GB) only with heavy apps closed. These are the standard sizes for this 30.5B-A3B architecture; `make model` prints and pins the exact size it downloads.

Then, as one switch: `rm models/MODEL.lock && make model && make model-down && make model-up && make smoke`. `make model` downloads, hashes and pins the file. Since this config also sets the Qwen template (`""`) and 32K context, don't start the server against the old 8B after changing it — switch the model in the same step. Use the Instruct/Coder (non-thinking) variant, not a "thinking" model — this agent does not parse `<think>` blocks, and the grammar-constrained `json` mode already gives reliable tool calls, so leave `AGENT_TOOL_MODE="json"`.

Steps to switch any model:

1. Set `MODEL_REPO` (and `MODEL_QUANTS` if its file names differ) in `config.env`, delete `models/MODEL.lock`, then run `make model`.
2. Run `make model-info`. If it says the template is embedded, set `LLAMA_CHAT_TEMPLATE=""`. If not, put the right Jinja template in `templates/` and point the setting at it.
3. Run `make model-down && make model-up && make smoke`. The smoke test should say `finished: on its own`.

## Updating pins

- **llama.cpp:** change `LLAMA_CPP_TAG` and `LLAMA_CPP_COMMIT` (`git ls-remote https://github.com/ggml-org/llama.cpp refs/tags/<tag>`), then `make llama`.
- **Ghidra:** change `GHIDRA_VERSION`, `GHIDRA_DATE` and `GHIDRA_SHA256` from the release page, then `make ghidra`.
- **pyghidra-mcp:** edit `ghidra/requirements.in` and re-lock: `uv pip compile ghidra/requirements.in --universal --python-version 3.12 --generate-hashes -o ghidra/requirements.lock`. Update `PYGHIDRA_MCP_VERSION`, then run `make ghidra`. For the agent, do the same with `agent/requirements.*` and `--python-version 3.10`, then `make setup`.

## Packaging the lab

`make package` writes `dist/re-lab-<date>-<time>.tar.gz` with only the files needed to run the lab: the `Makefile`, `README.md`, `config.env`, `.gitignore`, `agent/`, `ghidra/`, `llama/`, `sandbox/`, `scripts/`, `templates/`, `tests/` and the `.githooks/`/`.github/` security gate — about 32 files and 196 KB. The archive is built from that explicit list, not by excluding things, so these are never included:
- samples
- models
- Ghidra projects
- logs
- the llama.cpp build in `vendor/`
- `agent/.venv`
- `.run/`, which holds the API key and socket
- earlier packages in `dist/`

Before finishing, it scans the archive for any of those and deletes it if one slipped in.

```
$ make package
==> Contents:
    .gitignore
    Makefile
    README.md
    agent/agent.py
    ...
    templates/llama3.jinja
 ok  dist/re-lab-20261101-040733.tar.gz  (196K, 32 files)
     sha256 e912b720a412196632d91d31a5e60e96d469a0359a78348c7bd0d8e1335433eb
     to use it: tar -xzf re-lab-20261101-040733.tar.gz && cd re-lab && make all
```

On the other machine, unpack it and run `make all`. That downloads and builds the model, llama.cpp and the Ghidra image again, and `make setup` recreates the empty folders. `config.env` is packaged as it is, so check settings such as `LLAMA_BACKEND` and `GHIDRA_MEM` for the new machine.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `make setup` or `make ghidra`: *docker is installed but not running* | Start Docker Desktop / OrbStack (or `sudo systemctl start docker`) and re-run. |
| `make model-up` fails on macOS | Run `make model-fg` to watch the log. To see what the sandbox blocked: `log show --last 10m --style compact --predicate 'sender == "Sandbox"'`. |
| `make smoke`: *hit the token limit*, or replies contain `<\|im_end\|>` | The chat template doesn't match the model; see *Changing the model*. |
| Linux: no CUDA in `docker logs re-lab-llama` | The container can't see the GPU. If `docker run --rm --gpus all ubuntu nvidia-smi` fails, the NVIDIA Container Toolkit isn't configured. |
| Agent: *model server not started yet* | `make model-up`. `make status` shows what is running. |
| Agent: *Ghidra's search index failed to build* | `search_code` and `search_strings` are left out for that session; the reason is in the `logs/ghidra-*.log` named in the message. Images built before the permissions fix need `make ghidra`. |
| `search_code` / `search_strings`: *indexing is not complete* | Only with `--no-wait`: indexing is still running. `/bins` shows progress. |
| `decompile_function` times out | pyghidra-mcp stalls decompiles while it rebuilds a search index, which is why the agent waits for indexing at startup. To force a re-import of a sample, delete its line from `projects/<project>.re-lab-imported`. |
| *re-lab-ghidra-lab is still running* | A previous session is still saving. If it is stuck: `docker stop re-lab-ghidra-lab`. |
| `rename_variable` / `set_variable_type`: *Variable 'param_1' not found* | Decompiler names aren't saved variables. Set the function's prototype first (see *Editing variables*). |
| The model gives vague or wrong answers | `/decompile` the function yourself and ask about it, keep questions narrow, or try a stronger model. |

## Test status

**macOS, Apple Silicon (M3 Max, 48 GB):**
- `make setup`, plus the Metal build of llama-server
- model download and verification
- the sandboxed model server: about 43 tokens/s, stops correctly with the Llama 3 template, no sandbox denials
- `make ghidra`, including compiling Ghidra's decompiler for arm64
- agent sessions with the real model, with commands piped in and with `--once`
- every `/call` example in *Ghidra tools*, all 17 tools, including the variable-editing sequence
- every command at the `re-lab>` prompt
- `make projects` against the real projects folder

**Linux x86_64 (CPU only):**
- `make setup` and building the Ghidra image
- all Ghidra tools offline through `scripts/ghidra-mcp.sh`
- consecutive agent sessions over the Unix socket, with a scripted stand-in for the model
- the CPU model-server image with the real container flags
- `make projects` and `make delete-project`: the confirmation prompt and the refusals for a missing name, an unknown project and an invalid name (not the open-project check)
- `make package` from a folder full of samples, projects, logs and runtime state: the archive held only the lab files, unpacked identical to the source, and could be repackaged

**Not tested:** the CUDA image on a real NVIDIA GPU. The Linux steps above were checked on a CPU-only machine.

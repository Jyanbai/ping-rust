"""Codex 之后的工作流步骤加固：共用的解析、测试替身和检查工具（只给测试用）。

Codex 运行时沙箱可以写 ~/.cargo/bin，而它在 runner 的 PATH 里排在 /usr/bin 前面。
所以 Codex 之后的每个 run 步骤都用绝对路径的 bash、开头把 PATH 固定为 /usr/bin:/bin，
并用绝对路径调用外部命令，避免调用到沙箱里放的同名程序。
"""
import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
HARDENED_SHELL = "/usr/bin/bash --noprofile --norc -e -o pipefail {0}"
PATH_RESET = "PATH=/usr/bin:/bin\nexport PATH\n"
# workflow -> (job, 第一个运行 Codex 的步骤)
FLOWS = {
    "codex-dispatch.yml": ("codex", "Run Codex"),
    "codex-code-review.yml": ("review", "Run Codex review"),
    "codex-plan.yml": ("plan", "Run Codex plan"),
}
# 这些外部命令在 Codex 之后只能用绝对路径调用。
PINNED = (
    "awk", "base64", "cat", "chmod", "codex", "cp", "curl", "cut", "date", "diff", "env", "find",
    "gh", "git", "grep", "head", "jq", "ls", "mkdir", "mv", "node", "npm", "od", "python",
    "python3", "rm", "sed", "sha256sum", "sleep", "sort", "stat", "sudo", "tail", "tee",
    "timeout", "touch", "tr", "uniq", "wc", "xargs",
)
# 假的同名程序（放进 ~/.cargo/bin 等 PATH 前部）：被调用就记一笔并失败。
HIJACK_NAMES = PINNED + ("bash", "sh", "cargo", "rustc", "printf", "echo", "test", "true")
HIJACK_SCRIPT = "#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$*\" >> \"$HIJACK_LOG\"\nexit 97\n"


def install_hijack_bin(directory, log):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name in HIJACK_NAMES:
        path = directory / name
        path.write_text(HIJACK_SCRIPT.replace("$HIJACK_LOG", str(log)), encoding="utf-8")
        path.chmod(0o755)
    return directory


def _job_range(lines, job):
    start = lines.index(f"  {job}:")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^  \S", lines[i])), len(lines))
    return start, end


def steps(workflow):
    """返回 job 里 Codex 步骤及其之后的每一步：dict(name, shell, run, uses, env)。"""
    job, first = FLOWS[workflow]
    lines = (WORKFLOWS / workflow).read_text(encoding="utf-8").splitlines()
    js, je = _job_range(lines, job)
    starts = [i for i in range(js, je) if lines[i].startswith("      - name: ")]
    first_index = next(i for i in starts if lines[i] == f"      - name: {first}")
    result = []
    for k in [i for i in starts if i >= first_index]:
        end = next((i for i in starts if i > k), je)
        block = lines[k:end]
        step = {"name": block[0][len("      - name: "):], "shell": None, "run": None, "uses": None, "block": "\n".join(block)}
        for n, line in enumerate(block):
            if line.startswith("        shell: "):
                step["shell"] = line[len("        shell: "):]
            elif line.startswith("        uses: "):
                step["uses"] = line[len("        uses: "):]
            elif line.startswith("        run: "):
                if line == "        run: |":
                    body = []
                    for item in block[n + 1:]:
                        if item.strip() and not item.startswith(" " * 10):
                            break
                        body.append(item)
                    step["run"] = textwrap.dedent("\n".join(body)).rstrip("\n") + "\n"
                else:
                    step["run"] = line[len("        run: "):] + "\n"
        result.append(step)
    return result


def run_steps(workflow):
    return [s for s in steps(workflow) if s["run"] is not None]


def hardened_part(workflow, step):
    """Codex 步骤从 PATH 重置之后开始算；其余步骤是整段脚本。"""
    _, first = FLOWS[workflow]
    script = step["run"]
    if step["name"] == first:
        return script[script.index(PATH_RESET):]
    return script


def unpin(script):
    """给旧的行为测试用：去掉 PATH 重置并把绝对路径换回命令名，让测试里的假 gh 等生效。"""
    script = script.replace(PATH_RESET, "")
    names = "|".join(re.escape(n) for n in sorted(PINNED, key=len, reverse=True))
    return re.sub(rf"/usr/bin/({names})(?=[\s;|&)\"'`]|$)", r"\1", script)


# ---- 静态检查：找出处在命令位置的单词 ----
_KEYWORDS = {"then", "do", "else", "elif", "if", "while", "until", "!", "time"}


def command_words(script):
    """粗略的 bash 词法：跳过注释、引号内容（可跨行）和 heredoc 正文，返回处在命令位置的单词。"""
    words = []
    functions = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", script, flags=re.M))
    stack, at_cmd, i, n = ["cmd"], True, 0, len(script)
    pending_heredoc = None
    line_start = 0
    while i < n:
        ch = script[i]
        if ch == "\n":
            if stack[-1] == "cmd" and script[i - 1:i] != "\\":
                at_cmd = True
                line = script[line_start:i]
                m = re.search(r"<<-?\s*'(\w+)'", line) or re.search(r"<<-?\s*(\w+)\s*$", line)
                if m and len(stack) == 1:
                    pending_heredoc = m.group(1)
            line_start = i + 1
            i += 1
            if pending_heredoc:
                # 跳过 heredoc 正文直到结束行
                while i < n:
                    end = script.find("\n", i)
                    end = n if end < 0 else end
                    if script[i:end].strip() == pending_heredoc:
                        i = end
                        break
                    i = end + 1
                pending_heredoc = None
                line_start = i + 1 if i < n else n
                i += 1
            continue
        if stack[-1] == "dq":
            if ch == "\\":
                i += 2; continue
            if ch == '"':
                stack.pop(); i += 1; at_cmd = False; continue
            if script.startswith("$(", i):
                stack.append("cmd"); i += 2; at_cmd = True; continue
            i += 1; continue
        if ch == "#" and (i == 0 or script[i - 1] in " \t\n"):
            j = script.find("\n", i)
            i = n if j < 0 else j; continue
        if ch == "'":
            j = script.find("'", i + 1)
            i = n if j < 0 else j + 1; at_cmd = False; continue
        if ch == '"':
            stack.append("dq"); i += 1; at_cmd = False; continue
        if ch == "\\":
            i += 2; continue
        if script.startswith("$(", i):
            stack.append("cmd"); i += 2; at_cmd = True; continue
        if ch == ")" and len(stack) > 1:
            stack.pop(); i += 1; at_cmd = False; continue
        if ch in "|;&(" or (ch == "{" and script[i + 1:i + 2] in (" ", "\n", "")):
            i += 1; at_cmd = True; continue
        if ch in " \t" or (ch == "!" and at_cmd):
            i += 1; continue
        m = re.match(r"[A-Za-z0-9_./+-]+", script[i:i + 200])
        if not m:
            i += 1; at_cmd = False; continue
        word = m.group(0)
        rest = script[i + len(word):i + len(word) + 3]
        i += len(word)
        if at_cmd:
            if re.match(r"\+?=", rest) or rest.startswith("["):
                eq = re.match(r"\+?=", rest)
                i += len(eq.group(0)) if eq else 0
                if script.startswith("(", i):
                    i += 1; at_cmd = True
                else:
                    at_cmd = i >= n or script[i] in " \t"
                continue
            if rest.startswith("()"):
                at_cmd = False; continue
            if word in _KEYWORDS:
                continue
            if word not in functions:
                words.append(word)
                if word.endswith("/timeout"):
                    t = re.match(r"[ \t]+\S+[ \t]+([A-Za-z0-9_./+-]+)", script[i:i + 200])
                    if t:
                        words.append(t.group(1))
        at_cmd = False
    return words

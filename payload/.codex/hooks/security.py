#!/usr/bin/env python3
"""Codex guardrails equivalent to the Starter's visible-command restrictions.

Reads only a hook event, never executes its command or reads a secret file.
This is a guardrail, not a sandbox: opaque programs, later stdin and tool paths
outside PreToolUse still require the platform's permission controls.
"""
import fnmatch
import json
import re
import shlex
import sys
from pathlib import PurePosixPath

MARKER = "CODEX_STARTER_SECURITY_TEST_DENY"
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
READERS = {"cat", "tac", "head", "tail", "more", "less", "sed", "awk",
           "cut", "sort", "nl", "od", "xxd", "base64", "strings", "dd",
           "cp", "scp", "curl", "wget"}
REASONS = {
    "rm": "Starter: рекурсивное принудительное удаление запрещено. Используйте точное удаление отдельных проверенных файлов.",
    "chmod": "Starter: права 777 запрещены. Выберите минимальные права для конкретного файла.",
    "export": "Starter: export вместе с curl запрещён. Используйте существующий скрипт интеграции без вывода секретов.",
    "wget": "Starter: wget с переменными запрещён. Используйте проверенный буквальный адрес.",
    "env": "Starter: чтение полного .env/.env.local запрещено. Используйте grep/rg по имени одной конкретной переменной без контекстных строк.",
    "parse": "Starter: команду не удалось безопасно разобрать. Выполните простую команду отдельно.",
    "marker": "Контрольная проверка Starter: безопасный тестовый маркер отклонён.",
}


def secret_path(value):
    """Exact secret names and globs that can include them; .env.example is safe."""
    name = PurePosixPath(str(value).strip().lstrip("@")).name
    if name in {".env", ".env.local"}:
        return True
    return any(c in name for c in "*?[") and any(
        fnmatch.fnmatchcase(secret, name) for secret in (".env", ".env.local"))


def lex(command):
    parser = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>\n")
    parser.whitespace = " \t\r"
    parser.whitespace_split = True
    return list(parser)


def command_parts(command):
    """Split executable commands, retaining quoted shell wrapper arguments."""
    parts, current = [], []
    for token in lex(command):
        if token and all(c in ";&|()\n" for c in token):
            if current:
                parts.append(current)
                current = []
        else:
            current.append(token)
    if current:
        parts.append(current)
    return parts


def substitutions(text):
    """Visible $(...) and backticks outside single quotes are executable."""
    found, index, quote = [], 0, None
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            index += 2
            continue
        if quote == "'":
            if char == "'":
                quote = None
        elif char == "'" and quote is None:
            quote = "'"
        elif char == '"':
            quote = None if quote == '"' else '"'
        elif char == "`":
            end = text.find("`", index + 1)
            if end < 0:
                raise ValueError("unterminated substitution")
            found.append(text[index + 1:end])
            index = end
        elif text.startswith("$(", index) and not text.startswith("$((", index):
            start, end, level = index + 2, index + 2, 1
            inner_quote = None
            while end < len(text) and level:
                current = text[end]
                if current == "\\" and inner_quote != "'":
                    end += 2
                    continue
                if inner_quote:
                    if current == inner_quote:
                        inner_quote = None
                elif current in "'\"":
                    inner_quote = current
                elif current == "(":
                    level += 1
                elif current == ")":
                    level -= 1
                end += 1
            if level:
                raise ValueError("unterminated substitution")
            found.append(text[start:end - 1])
            index = end - 1
        index += 1
    return found


def without_heredoc_data(command):
    """Keep shell lines; heredoc bodies are data unless a shell consumes them."""
    # A quoted argument may contain physical newlines. Whole-command lexing
    # handles them; line-by-line heredoc extraction is unnecessary otherwise.
    if "<<" not in command:
        return command, []
    lines = command.splitlines(keepends=True)
    kept, bodies = [], []
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        # Heredoc-looking text can itself be inside a multiline quoted argument.
        # Accumulate the logical shell line before looking for delimiters.
        while True:
            try:
                tokens = lex(line)
                break
            except ValueError:
                if index >= len(lines):
                    raise
                line += lines[index]
                index += 1
        kept.append(line)
        delimiters = []
        for n, token in enumerate(tokens[:-1]):
            if token in ("<<", "<<-"):
                delimiter = tokens[n + 1]
                # shlex treats the '-' in <<-EOF as part of the next word.
                strip_tabs = token == "<<-" or delimiter.startswith("-")
                delimiters.append((delimiter.lstrip("-") if strip_tabs else delimiter, strip_tabs))
        for delimiter, strip_tabs in delimiters:
            body = []
            while index < len(lines):
                content = lines[index]
                index += 1
                comparable = content.lstrip("\t") if strip_tabs else content
                if comparable.rstrip("\r\n") == delimiter:
                    break
                body.append(content)
            else:
                raise ValueError("unterminated heredoc")
            bodies.append((line, "".join(body)))
    return "".join(kept), bodies


def unwrap(tokens):
    """Find the command after common transparent wrappers and assignments."""
    tokens = list(tokens)
    while tokens:
        name = PurePosixPath(tokens[0]).name
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
            tokens.pop(0)
        elif name in {"command", "builtin", "exec", "nohup", "do", "then", "else", "if", "while", "until", "!"}:
            tokens.pop(0)
            if tokens and tokens[0] == "--":
                tokens.pop(0)
        elif name == "env":
            tokens.pop(0)
            while tokens and tokens[0] in {"-i", "--ignore-environment", "--"}:
                tokens.pop(0)
        elif name == "sudo":
            tokens.pop(0)
            while tokens and tokens[0].startswith("-"):
                option = tokens.pop(0)
                if option in {"-u", "-g", "-h", "-p", "-C", "-T"} and tokens:
                    tokens.pop(0)
        else:
            break
    return tokens


def targeted_env_search(tokens):
    """Permit just one literal variable-name pattern, never inverse/context."""
    operands, patterns, index = [], [], 1
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == "--":
            operands.extend(tokens[index:])
            break
        if token.startswith("--"):
            if token in {"--line-number", "--no-heading", "--with-filename",
                         "--no-filename", "--fixed-strings"}:
                continue
            return False
        if token.startswith("-"):
            if token == "-e" and index < len(tokens):
                patterns.append(tokens[index])
                index += 1
            elif re.fullmatch(r"-[nHhF]+", token):
                continue
            else:
                return False
        else:
            operands.append(token)
    if not patterns and operands:
        patterns.append(operands.pop(0))
    if len(patterns) != 1 or not operands:
        return False
    pattern = patterns[0]
    return bool(re.fullmatch(r"\^?(?:export )?[A-Za-z_][A-Za-z0-9_]*=?", pattern))


def search_operands(tokens):
    """Separate grep/rg file operands from patterns and option values.

    A glob supplied to -g/--glob is a filter, not a file being opened. Pattern
    files and ignore files are inputs too, so return them separately. This
    parses common documented options, not arbitrary executable extensions.
    """
    value_options = {
        "-g", "--glob", "--iglob", "--include", "--exclude", "--exclude-dir",
        "-t", "--type", "-T", "--type-not", "--type-add", "--type-clear",
        "-A", "--after-context", "-B", "--before-context", "-C", "--context",
        "-m", "--max-count", "--max-depth", "-j", "--threads", "--encoding",
        "--color", "--colors", "--sort", "--sortr", "--path-separator",
        "--replace", "-r", "--label", "--binary-files", "--directories",
        "--devices", "--max-columns", "--max-filesize", "--context-separator",
    }
    # grep -r is a flag; rg -r takes a replacement string.
    if PurePosixPath(tokens[0]).name == "grep":
        value_options.discard("-r")
    input_options = {"-f", "--file", "--ignore-file", "--exclude-from"}
    pattern_options = {"-e", "--regexp"}
    operands, inputs = [], []
    has_pattern, index = False, 1
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == "--":
            operands.extend(tokens[index:])
            break
        option, equals, value = token.partition("=")
        options = value_options | input_options | pattern_options
        if option in options:
            if not equals and index < len(tokens):
                value = tokens[index]
                index += 1
            if option in input_options:
                inputs.append(value)
                if option in {"-f", "--file"}:
                    has_pattern = True
            elif option in pattern_options:
                has_pattern = True
            continue
        if len(token) > 2 and token[:2] in {"-e", "-f", "-g"}:
            if token[:2] == "-f":
                inputs.append(token[2:])
            if token[:2] in {"-e", "-f"}:
                has_pattern = True
            continue
        if not token.startswith("-"):
            operands.append(token)
    files_only = PurePosixPath(tokens[0]).name == "rg" and "--files" in tokens
    if not has_pattern and not files_only and operands:
        operands.pop(0)
    return operands, inputs


def check_command(command, depth=0):
    if depth > 6:
        return REASONS["parse"]
    try:
        executable, bodies = without_heredoc_data(command)
        parts = [unwrap(p) for p in command_parts(executable)]
        nested_commands = substitutions(executable)
    except ValueError:
        return REASONS["parse"]
    for nested in nested_commands:
        reason = check_command(nested, depth + 1)
        if reason:
            return reason
    programs = {PurePosixPath(p[0]).name for p in parts if p}
    if "export" in programs and "curl" in programs:
        return REASONS["export"]
    for tokens in parts:
        if not tokens:
            continue
        name, args = PurePosixPath(tokens[0]).name, tokens[1:]
        if any(MARKER in token for token in tokens):
            return REASONS["marker"]
        if name == "rm":
            options = []
            for token in args:
                if token == "--":
                    break
                if token.startswith("-"):
                    options.append(token)
            short = "".join(t[1:] for t in options if not t.startswith("--"))
            recursive = "r" in short or "R" in short or "--recursive" in options
            force = "f" in short or "--force" in options
            if recursive and force:
                return REASONS["rm"]
        if name == "chmod" and any(re.fullmatch(r"0?777", arg) for arg in args):
            return REASONS["chmod"]
        if name == "wget" and any("$" in arg or "`" in arg for arg in args):
            return REASONS["wget"]
        read_operands = [arg[3:] if name == "dd" and arg.startswith("if=")
                         else arg for arg in args]
        if name in {"grep", "rg"}:
            read_operands, auxiliary_inputs = search_operands(tokens)
            if any(secret_path(arg) for arg in auxiliary_inputs):
                return REASONS["env"]
        if any(secret_path(arg) for arg in read_operands):
            if name in {"grep", "rg"}:
                if not targeted_env_search(tokens):
                    return REASONS["env"]
            elif name in READERS or name in {"source", "."}:
                return REASONS["env"]
        if any(token.startswith("<") and i + 1 < len(tokens)
               and secret_path(tokens[i + 1]) for i, token in enumerate(tokens)):
            return REASONS["env"]
        if name in SHELLS:
            for i, arg in enumerate(args):
                if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
                    if i + 1 < len(args):
                        reason = check_command(args[i + 1], depth + 1)
                        if reason:
                            return reason
                    break
        if name in {"eval"}:
            reason = check_command(" ".join(args), depth + 1)
            if reason:
                return reason
        # Inline interpreter reads are visible; opaque script files stay under
        # normal permissions. Existing report scripts can read their JSON keys.
        if name.startswith(("python", "node", "ruby", "perl")):
            inline = " ".join(args)
            if inline_env_read(inline):
                return REASONS["env"]
    for opener, body in bodies:
        commands = [unwrap(p) for p in command_parts(opener)]
        names = {PurePosixPath(p[0]).name for p in commands if p}
        if names & SHELLS:
            reason = check_command(body, depth + 1)
            if reason:
                return reason
        elif any(n.startswith(("python", "node", "ruby", "perl")) for n in names):
            if inline_env_read(body):
                return REASONS["env"]
        # Unquoted heredocs perform command substitution even when consumed as
        # text; quoted heredocs used for docs/patches do not.
        if not re.search(r"<<-?\s*['\"\\]", opener):
            try:
                for nested in substitutions(body):
                    reason = check_command(nested, depth + 1)
                    if reason:
                        return reason
            except ValueError:
                return REASONS["parse"]
    return None


def inline_env_read(text):
    literal = r"['\"](?:[^'\"\n]*/)?\.env(?:\.local)?['\"]"
    # Match a secret operand of a visible read, not an unrelated filename
    # mentioned elsewhere in a script that happens to read ordinary files.
    if re.search(r"\b(?:readFileSync|readFile|read)\(\s*" + literal, text):
        return True
    if re.search(r"\bPath\(\s*" + literal + r"\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(", text):
        return True
    for match in re.finditer(r"\bopen\(\s*" + literal + r"(?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
        mode = match.group(1) or "r"
        if "+" in mode or not any(flag in mode for flag in "wax"):
            return True
    # Also cover a simple same-variable handoff, without interpreting code.
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(?:Path\(\s*)?" + literal, text):
        variable = re.escape(match.group(1))
        suffix = text[match.end():]
        if re.search(r"\b" + variable + r"\s*\.\s*(?:read_text|read_bytes|open)\s*\(", suffix):
            return True
        if re.search(r"\b(?:open|readFileSync|readFile|read)\(\s*" + variable + r"\b", suffix):
            return True
    return False


def inspect_event(event):
    name = str(event.get("tool_name", ""))
    data = event.get("tool_input", {})
    if not isinstance(data, dict):
        return None
    if name in {"Bash", "bash", "exec_command", "shell_command", "shell"}:
        command = data.get("command", data.get("cmd", ""))
        if isinstance(command, list):
            command = shlex.join(str(part) for part in command)
        return check_command(command) if isinstance(command, str) else REASONS["parse"]
    if re.search(r"(?:read|open_file|view_file)", name, re.I):
        for key in ("file_path", "path", "filename", "paths"):
            value = data.get(key, [])
            for path in value if isinstance(value, list) else [value]:
                if isinstance(path, str) and secret_path(path):
                    return REASONS["env"]
    return None


def main():
    try:
        event = json.load(sys.stdin)
        reason = inspect_event(event) if isinstance(event, dict) else REASONS["parse"]
    except (ValueError, TypeError):
        reason = REASONS["parse"]
    output = {}
    if reason:
        output = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                  "permissionDecision": "deny", "permissionDecisionReason": reason}}
    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()

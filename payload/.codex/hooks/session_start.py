#!/usr/bin/env python3
"""Static navigation reminder; no project or transcript files are opened."""
import json


def main():
    context = (
        "Codex Starter: начни с текущей просьбы пользователя и AGENTS.md. "
        "Общий процесс — .starter/workflow.md; краткий контекст проекта — "
        "PROJECT.md, если он существует. Для продолжения найди действующий "
        "план и последний checkpoint в plans/ или в уже принятом проектом "
        "месте. Используй существующие документы, не создавай второй набор "
        "контекста и не запускай интервью повторно без запроса. Сохраняй "
        "sandbox и порядок подтверждения действий. Не читай секреты и "
        "транскрипты ради этого напоминания. Наличие этого сообщения "
        "не подтверждает, что другие hooks включены или проверки пройдены."
    )
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart", "additionalContext": context}}, ensure_ascii=False))


if __name__ == "__main__":
    main()

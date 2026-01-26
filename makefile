.PHONY: init
init:
	@echo "Инициализация проекта..."
	@which pre-commit >/dev/null 2>&1 || pip install pre-commit
	@which npm >/dev/null 2>&1 && npm install --save-dev @commitlint/cli @commitlint/config-conventional || echo "npm не найден, пропускаем установку Node.js пакетов"
	pre-commit install --hook-type commit-msg
	pre-commit autoupdate
	@echo "Готово! Запустите: make test-hooks"

.PHONY: test-hooks
test-hooks:
	pre-commit run --all-files

.PHONY: hooks
hooks:
	pre-commit run --all-files --hook-stage commit-msg
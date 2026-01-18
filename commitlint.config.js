module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',     // Фича
        'fix',      // Фикс
        'docs',     // Документация
        'style',    // Стиль/форматирование
        'refactor', // Рефакторинг
        'test',     // Тесты
        'chore',    // Обслуживание
        'build',    // Сборка
        'ci',       // CI/CD
        'perf',     // Производительность
        'revert'    // Откат
      ]
    ],
    // Разрешаем русский язык в описании
    'subject-case': [0, 'never'],
    // Увеличиваем максимальную длину заголовка для русского текста
    'header-max-length': [2, 'always', 200]
  }
};

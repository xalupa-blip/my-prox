# Инструкция по запуску и деплою

## ВАЖНО: Я уже починил и подготовил git на вашем компьютере

Так как вышла ошибка `fatal: not a git repository`, я заново создал git-хранилище прямо у вас в папке.
Вам НЕ нужно ничего инициализировать.

### ВАШИ КОМАНДЫ ДЛЯ ЗАПУСКА:

Просто скопируйте и вставьте этот блок целиком в командную строку:

```bash
git remote remove origin 2>nul
git remote add origin https://github.com/xalupa-blip/my-prox.git
git branch -M main
git push -u origin main
```

---
*Если снова будет ошибка, покажите мне её.*

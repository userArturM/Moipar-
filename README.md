# Мои пароли Pro 4.0

Приватный репозиторий приложения для Windows.

## Важно
Исходники приложения пока необходимо загрузить из архива `MoiParoli-Pro-4.0-Hello-UI-source.zip` (содержимое вложенной папки, не ZIP целиком). Архив содержит `moi_paroli.py`, `windows_hello.py`, `browser_host.py`, `installer.iss`, `icon.ico`, `tests/`, `browser_extension/` и остальные файлы проекта.

После загрузки исходников автоматически запускается `Windows build`. При успешной сборке во вкладке **Actions → последний запуск → Artifacts** появятся архивы с:
- `MoiParoli.exe` (portable)
- `MoiParoli-Setup.exe` (установщик).

Не загружайте реальные `vault.dat`, резервные копии хранилища или секреты в GitHub. Windows Hello и новый интерфейс требуют реального тестирования на Windows 10/11. Перед любыми обновлениями сделайте резервную копию vault.dat.

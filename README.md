# Программа-детектор подозрительной активности  

## Установка и запуск
```bash
make ARGS="абсолютный путь к тестовой папке"
```
**1) Запускать надо через sudo;**

**2) Создается точка монтирования тестовой директории, иначе будет отслеживаться вся файловая система.**

## Для сборки без запуска
```bash
make fntf_detect
```
При запуске необходимо передать путь к тестовой директории, за которой детектор будет следить.

## Запуск вируса-шифровальщика

```bash
python3 encrypt-files.py "абсолютный путь к тестовой папке"
```
Он выводит свой PID, чтобы можно было убедиться, что именно его остановил наш детектор.
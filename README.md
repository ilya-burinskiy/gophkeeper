Переменные окружения сервера:
```
RUN_ADDRESS - адрес и порт запуска сервиса
MASTER_KEY - мастер-ключ для шифрования ключей, которыми шифруются данные пользователей
SERVER_CRT_PATH - абсолютный путь к TLS сертификату
SERVER_KEY_PATH - абсолютный путь к приватному ключу TLS сертификата
DATABASE_URI - адрес сервера PostgeSQL
```
Пример запуска сервера:
```
RUN_ADDRESS='localhost:8000' \
SERVER_CRT_PATH='/path/to/server.crt' \
SERVER_KEY_PATH='/path/to/server.key' \
DATABASE_URI='postgres://database:password@localhost:5432/database' \
go run . 
```
Переменные окружения клиента:
```
BASE_URL - адрес сервера. Например http://localhost:8000
```

CLI клиента:
- Регистрация
    ```
    Usage of register:
        -login string
            your login
        -password string
            your password
    ```
- Аутентификация
    ```
    Usage of authenticate:
        -login string
            your login
        -password string
            your password
    ```
- Получить список секретов в виде архива пользователя
    ```
    Usage of get-secrets:
        -jwt string
            authentication JWT
        -output string
            output filename (default "archive.zip")
    ```
- Создать пару логин/пароль
    ```
    Usage of create-creds:
        -jwt string
            authentication JWT
        -login string
            login
        -password string
            password
    ```
- Создать данные банковской карты
    ```
    Usage of create-credit-card:
    -cvv2 string
        credit card CVV2
    -date string
        credit card expriry date in RFC3339 format
    -jwt string
        authentication JWT
    -name string
        credit card owner name
    -number string
        credit card number
    ```
- Создать бинарные данные
    ```
    Usage of create-bin-data:
    -jwt string
        authentication JWT
    -path string
        file path
    ```
- Обновить пару логин/пароль
    ```
    Usage of update-creds:
        -jwt string
            authentication JWT
        -login string
            login
        -password string
            password
    ```
- Обновить данные банковской карты
    ```
    Usage of update-credit-card:
    -cvv2 string
        credit card CVV2
    -date string
        credit card expriry date in RFC3339 format
    -jwt string
        authentication JWT
    -name string
        credit card owner name
    -number string
        credit card number
    ```
- Обновить бинарные данные
    ```
    Usage of update-bin-data:
    -jwt string
        authentication JWT
    -path string
        file path
    ```
- Удалить секрет
    ```
    Usage of delete:
    -id int
        secret ID
    -jwt string
        authentication JWT
    ```

Пример команды:
```
BASE_URL='http://localhost:8000' go run . create-creds \
     -jwt='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' \
     -login='some_login' \
     -password='some_pwd'
```

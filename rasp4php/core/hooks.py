CODE_EXECUTION = {
    'eval': {'hook':'compile_string', 'depends': set()},
    'assert': {'hook':'compile_string', 'depends': set()},
    'create_function': {'hook':'compile_string', 'depends': set()}
}

COMMAND_EXECUTION = {
    # TODO: pcntl_exec
    'exec': {'hook':'php_exec', 'depends': set()},
    'proc_open': {'hook':'zif_proc_open', 'depends': set()},
    'shell_exec': {'hook':'zif_shell_exec', 'depends': set()},
}

FILE_OPERATION = {
    # file inclusion,  file_read_write
    'include*': {'hook':'php_resolve_path', 'depends': set()},
    'require*': {'hook':'php_resolve_path', 'depends': set()},
    'file_*': {'hook':'php_stream_locate_url_wrapper', 'depends': set()}
}

FILE_UPLOAD = {
    'move_uploaded_file': {'hook':'zif_move_uploaded_file', 'depends': set()}
}

SQL_INJECTION = {
    #'depends': set(['PDO', 'pdo-mysql', 'pdo-sqlite', 'mysqli', 'mysqlnd'])
}

DESERIALIZATION = {
    'unserialize': {'hook':'zif_unserialize', 'depends': set()}
}

SSRF = {
    'curl_setopt': {'hook':'curl_easy_setopt', 'depends': set(['curl',])},
    'curl_multi_setopt': {'hook':'curl_multi_setopt', 'depends': set(['curl',])},
    'curl_share_setopt': {'hook':'curl_share_setopt', 'depends': set(['curl',])},
    'fsockopen': {'hook':'_php_stream_xport_create', 'depends': set()},
    'socket_connect': {'hook':'zif_socket_connect', 'depends': set()},
}

INFO_LEAKING = {
    # TODO: getcwd, get_current_user, getmypid, posix_get* etc.
    'phpinfo': {'hook':'zif_phpinfo', 'depends': set()},
    'getenv': {'hook':'zif_getenv', 'depends': set()}
}

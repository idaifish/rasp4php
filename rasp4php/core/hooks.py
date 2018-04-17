CODE_EXECUTION = {
    'depends': [],
    'hooks': {
        'eval': 'compile_string',
        'assert': 'compile_string',
        'create_function': 'compile_string',
    }
}

COMMAND_EXECUTION = {
    'depends': [],
    'hooks': {
        # TODO: pcntl_exec
        'exec': 'php_exec',
        'proc_open': 'zif_proc_open',
        'shell_exec': 'zif_shell_exec',
    }
}

FILE_OPERATION = {
    'depends': [],
    'hooks': {
        # file inclusion,  file_read_write
        'include*': 'php_resolve_path',
        'require*': 'php_resolve_path',
        'file_*': 'php_stream_locate_url_wrapper',
    }
}

FILE_UPLOAD = {
    'depends': [],
    'hooks': {
        'move_uploaded_file': 'zif_move_uploaded_file'
    }
}

SQL_INJECTION = {
    'depends': ['PDO', 'pdo-mysql', 'pdo-sqlite', 'mysqli', 'mysqlnd'],
    'hooks': {
        # mysqli->query etc.
    }
}

DESERIALIZATION = {
    'depends': [],
    'hooks': {
        'unserialize': 'zif_unserialize'
    }
}

SSRF = {
    'depends': ['curl', ],
    'hooks': {
        'curl_*': 'php_curl_option_str'
    }
}

INFO_LEAKING = {
    'depends': [],
    'hooks': {
        # TODO: getcwd, get_current_user, getmypid, posix_get* etc.
        'phpinfo': 'zif_phpinfo',
        'getenv': 'zif_getenv',
    }
}

CODE_EXECUTION = {
    'eval': 'compile_string',
    'assert': 'compile_string',
    'create_function': 'compile_string',

}

COMMAND_EXECUTION = {
    # TODO: pcntl_exec
    'exec': 'php_exec',
    'proc_open': 'zif_proc_open',
    'shell_exec': 'zif_shell_exec',
}

FILE_OPERATION = {
    # file inclusion,  file_read_write
    'include*': 'php_resolve_path',
    'require*': 'php_resolve_path',
    'file_*': 'php_stream_locate_url_wrapper',
}

FILE_UPLOAD = {
    'move_uploaded_file': 'zif_move_uploaded_file'
}

SQL_INJECTION = (
    # mysqli->query etc.
)

DESERIALIZATION = {
    'unserialize': 'zif_unserialize'
}

SSRF = {
    'curl_*': 'php_curl_option_str'
}

INFO_LEAKING = {
    # TODO: getcwd, get_current_user, getmypid, posix_get* etc.
    'phpinfo': 'zif_phpinfo',
    'getenv': 'zif_getenv',
}

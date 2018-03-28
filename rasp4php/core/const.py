# Hooks

CODE_EXECUTION = (
    # eval, assert, create_function etc.
    'compile_string',
)

COMMAND_EXECUTION = (
    # shell_exec, proc_open, exec etc.
    'php_exec',
    'zif_proc_open',
    'zif_shell_exec'
)

FILE_INCLUSION = (
    # include* require*
)

FILE_READ_WRITE = (
    # scandir, file_get_contents, file_put_contents
    'zif_scandir',
)

FILE_UPLOAD = (
    # move_uploaded_file
)

SQL_INJECTION = (
    # mysqli->query etc.
)

DESERIALIZATION = (
    # unserialize
    #'zif_unserialize',
)

SSRF = (
    # curl etc.
)

INFO_LEAKING = (
    # phpinfo, getenv, getcwd, get_current_user, getmypid, posix_get* etc.
    'zif_phpinfo',
    'zif_getenv'
)
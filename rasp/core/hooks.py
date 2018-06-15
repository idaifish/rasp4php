from pathlib import Path
from collections import namedtuple


Hook = namedtuple('Hook', ('name', 'script'))


class HooksManager(object):
    CODE_EXECUTION = {
        'eval': {'hook': 'compile_string', 'depends': set()},
        'assert': {'hook': 'compile_string', 'depends': set()},
        'create_function': {'hook': 'compile_string', 'depends': set()}
    }

    COMMAND_EXECUTION = {
        'exec': {'hook': 'php_exec', 'depends': set()},
        'proc_open': {'hook': 'zif_proc_open', 'depends': set()},
        'shell_exec': {'hook': 'zif_shell_exec', 'depends': set()},
        'popen': {'hook': 'zif_popen', 'depends': set()},
    }

    FILE_OPERATION = {
        'include*': {'hook': 'php_resolve_path', 'depends': set()},
        'require*': {'hook': 'php_resolve_path', 'depends': set()},
        'file_*': {'hook': 'php_stream_locate_url_wrapper', 'depends': set()}
    }

    FILE_UPLOAD = {
        'move_uploaded_file': {'hook': 'zif_move_uploaded_file', 'depends': set()}
    }

    DB_OPERATION = {
        # TODO: mongodb, sqlite
        'mysqli_query': {'hook': 'php_mysqlnd_cmd_write', 'depends': set(['mysqlnd', ])}
    }

    DESERIALIZATION = {
        'unserialize': {'hook': 'zif_unserialize', 'depends': set()}
    }

    NETWORK_ACCESS = {
        'curl_setopt': {'hook': 'curl_easy_setopt', 'depends': set(['curl', ])},
        'curl_multi_setopt': {'hook': 'curl_multi_setopt', 'depends': set(['curl', ])},
        'curl_share_setopt': {'hook': 'curl_share_setopt', 'depends': set(['curl', ])},
        'fsockopen': {'hook': '_php_stream_xport_create', 'depends': set()},
        'socket_connect': {'hook': 'zif_socket_connect', 'depends': set()},
    }

    INFO_LEAKING = {
        'phpinfo': {'hook': 'zif_phpinfo', 'depends': set()},
        'getenv': {'hook': 'zif_getenv', 'depends': set()}
    }

    XXE = {
        'xml_load_external_entity': {'hook': 'xmlLoadExternalEntity', 'depends': set(['libxml', ])},
    }

    hooks = {
        'code_execution': CODE_EXECUTION,
        'command_execution': COMMAND_EXECUTION,
        'file_upload': FILE_UPLOAD,
        'file_operation': FILE_OPERATION,
        'network_access': NETWORK_ACCESS,
        'info_leak': INFO_LEAKING,
        'database_operation': DB_OPERATION,
        'deserialization': DESERIALIZATION,
        'xml_external_entity': XXE,
    }

    hook_script_base = Path(__file__).parents[1] / 'hooks'

    hook_script_template = """
    {php_api}
    Interceptor.attach(Module.findExportByName(null, '{func_name}'), {callback});
    """

    def get_hooks(self):
        return self.hooks.values()

    def remove_hooks(self, name):
        self.hooks.pop(name)
        return self.hooks.values()

    def get_php_api(self):
        return (self.hook_script_base / 'php.js').read_text()

    def get_hook_scripts(self, environment):
        fpm_modules = environment['fpm_enabled_modules']
        hook_funcs = []
        hook_scripts = []
        for f in self.get_hooks():
            for k, v in f.items():
                if v['depends'].issubset(set(fpm_modules)):
                    hook_funcs.append(v['hook'])

        for hook_func in set(hook_funcs):
            callback_path = self.hook_script_base / \
                environment['fpm_version'] / (hook_func + ".js")
            script = self.hook_script_template.format(
                php_api=self.get_php_api(),
                func_name=hook_func,
                callback=callback_path.read_text()
            )
            hook_scripts.append(Hook(hook_func, script))

        return hook_scripts

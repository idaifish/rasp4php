/**
 * Retrieve INI Config
 */
function ini_get (key) {
    var ini_get_addr = Module.findExportByName(null, 'zend_ini_string');
    var _ini_get = new NativeFunction(ini_get_addr, 'pointer', ['pointer', 'int', 'int']);
    var ini_key = Memory.allocUtf8String(key)

    return Memory.readCString(_ini_get(ini_key, key.length, 0))
}

function baselineCheck () {
    const sensitive_ini = [
        'allow_url_include',
        'allow_url_fopen',
        'auto_prepend_file',
        'auto_append_file',
        'expose_php',
        'display_errors',
        'open_basedir',
        'short_open_tag',
        'yaml.decode_php',
    ];
    var result = {}

    sensitive_ini.forEach(function (key) {
        result[key] = ini_get(key);
    });

    return result;
}

send(baselineCheck());


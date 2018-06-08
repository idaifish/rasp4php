{
  /*
    void zif_shell_exec(zend_execute_data *, zval *);
      - shell_exec
   */
  onEnter: function (args) {
    var message = {
        function: "shell_exec",
        args : [],
        filename: "",
        lineno: -1,
        context: 'command',
        type: 'command_execution'
    };
    var zendParseParametersAddr = Module.findExportByName(null, 'zend_parse_parameters');
    var zendParseParameters = new NativeFunction(zendParseParametersAddr, 'void', ['int', 'pointer', 'pointer', 'pointer']);
    var fmt = Memory.allocUtf8String('s');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    zendParseParameters(1, fmt, cmd, cmdLen);

    message.args.push(Memory.readCString(Memory.readPointer(cmd)));
    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    var sapi_getenv_addr = Module.findExportByName(null, 'sapi_getenv');
    var sapi_getenv = new NativeFunction(sapi_getenv_addr, 'pointer', ['pointer', 'int']);
    var envArray = ['SERVER_ADDR', 'SERVER_NAME', 'QUERY_STRING', 'DOCUMENT_ROOT', 'REMOTE_ADDR', 'REQUEST_URI'];
    var getenv = function (env) {
        var envName= Memory.allocUtf8String(env);
        var envValue = sapi_getenv(envName, env.length);
        return Memory.readCString(envValue);
    }
    message.query_string = getenv("QUERY_STRING");
    message.remote_addr = getenv("REMOTE_ADDR");
    message.request_uri = getenv("REQUEST_URI");

    send(message);
  },
  // onLeave: function (retval) {
  // }
}

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
          lineno: -1
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

    send(message);
  },
  // onLeave: function (retval) {
  // }
}

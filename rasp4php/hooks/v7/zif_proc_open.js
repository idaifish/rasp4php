{
  /*
    void zif_proc_open(zend_execute_data *, zval *);
      - popen_open
   */
  onEnter: function (args) {
    var message = {
          function: "proc_open",
          args : [],
          filename: "",
          lineno: -1
        };
    var zendParseParametersAddr = Module.findExportByName(null, 'zend_parse_parameters');
    var zendParseParameters = new NativeFunction(zendParseParametersAddr, 'pointer', ['int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    var fmt = Memory.allocUtf8String('saz/|s!a!a!');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);
    var descriptorspec = Memory.alloc(Process.pointerSize);
    var pipes = Memory.alloc(Process.pointerSize);
    var cwd = Memory.alloc(Process.pointerSize);
    var cwdLen = Memory.alloc(Process.pointerSize);
    var environment = Memory.alloc(Process.pointerSize);
    var otherOptions  = Memory.alloc(Process.pointerSize);

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    zendParseParameters(6, fmt, cmd, cmdLen, descriptorspec, pipes, cwd, cwdLen, environment, otherOptions);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();
    message.args.push(Memory.readCString(Memory.readPointer(cmd)))

    send(message);
  },
  onLeave: function (retval) {
  }
}

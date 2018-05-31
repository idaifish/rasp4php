{
  onEnter: function (args) {
    var message = {
        function: "popen",
        args : [],
        filename: "",
        lineno: -1,
        context: 'command',
        type: 'command_execution'
    };
    var zendParseParametersAddr = Module.findExportByName(null, 'zend_parse_parameters');
    var zendParseParameters = new NativeFunction(zendParseParametersAddr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    var fmt = Memory.allocUtf8String('ps');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);
    var mode = Memory.alloc(Process.pointerSize);
    var modeLen = Memory.alloc(Process.pointerSize);

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    zendParseParameters(2, fmt, cmd, cmdLen, mode, modeLen);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();
    message.args.push(Memory.readCString(Memory.readPointer(cmd)))
    message.args.push(Memory.readCString(Memory.readPointer(mode)))

    send(message);
  },
  // onLeave: function (retval) {
  // }
}
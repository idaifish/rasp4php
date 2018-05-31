{
  onEnter: function (args) {
    var message = {
        function: "socket_*",
        args : [],
        filename: "",
        lineno: -1,
        context: 'url',
        type: 'network_access'
    };

    var zendParseParametersAddr = Module.findExportByName(null, 'zend_parse_parameters');
    var zendParseParameters = new NativeFunction(zendParseParametersAddr, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
    var fmt = Memory.allocUtf8String('rs|l');
    var socket = Memory.alloc(Process.pointerSize);
    var addr = Memory.alloc(Process.pointerSize);
    var addrlen = Memory.alloc(Process.pointerSize);
    var port = Memory.alloc(Process.pointerSize);

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    zendParseParameters(3, fmt, socket, addr, addrlen, port);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();
    message.args.push(Memory.readCString(Memory.readPointer(addr)));
    message.args.push(Memory.readUInt(port));

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}

{
  onEnter: function (args) {
    var message = {
        function: "file_*",
        args : [],
        filename: "",
        lineno: -1,
        context: 'file',
        type: 'file_operation'
    };

    var openedFilename = Memory.readCString(args[0]);
    message.args.push(openedFilename);

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    if (message.filename !== '[no active file]') {
      send(message);
    }
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
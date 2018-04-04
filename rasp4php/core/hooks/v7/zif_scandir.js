{
  onEnter: function (args) {
    var message = {
        function: "scandir",
        args : [],
        filename: "",
        lineno: -1
    };
    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
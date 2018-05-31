{
  onEnter: function (args) {
    var message = {
        function: "fsockopen*",
        args : [],
        filename: "",
        lineno: -1,
        context: 'url',
        type: 'network_access'
    };

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    message.args.push(Memory.readCString(args[0]));

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
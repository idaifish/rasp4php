{
  onEnter: function (args) {
    var message = {
        function: "mysqli_*",
        args : [],
        filename: "",
        lineno: -1,
        context: 'sql',
        type: 'database_operation'
    };

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    var sql = Memory.readCString(Memory.readPointer(args[0].add(32)));
    if (sql !== null) {
      message.args.push(sql);
      send(message);
    }
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
{
  onEnter: function (args) {
    var CURLOPT_URL = 10002;

    if (args[1].toInt32() === CURLOPT_URL) {
      var message = {
          function: "curl",
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

      message.args.push(Memory.readCString(args[2]));

      send(message);
    }
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
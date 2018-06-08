{
  onEnter: function (args) {
    var CURLOPT_URL = 10002;

    if (args[1].toInt32() === CURLOPT_URL) {
      var message = {
          function: "curl*",
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

      message.args.push(Memory.readCString(args[2]));

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
    }
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}
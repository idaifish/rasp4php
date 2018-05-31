{
    /*
     *  int php_exec(int type, char *cmd, zval *array, zval *return_value)
     *    - system()
     *    - exec()
     */
    onEnter: function (args) {
      var message = {
          function: "",
          args : [],
          filename: "",
          lineno: -1,
          context: 'command',
          type: 'command_execution'
      };
      var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
      var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
      var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
      var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

      switch (args[0].toString()) {
        case '0x0':
          message.function = "exec";
          break;
        case '0x1':
          message.function = "system";
          break;
        case '0x2':
          message.function = "exec";
          break;
        case '0x3':
          message.function = "passthru";
          break;
        default:
          message.function = "system";
      }

      message.args.push(Memory.readCString(args[1]));
      message.filename = Memory.readCString(ptr(getFilename()));
      message.lineno = getLineno();

      send(message);
    },

    // onLeave: function (retval) {
    // }
}

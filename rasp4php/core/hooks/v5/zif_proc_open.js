{
  /*
    void zif_proc_open(zend_execute_data *, zval *);
      - popen_open
   */
  onEnter: function (args) {
    var message = {
      function: PHP.getFunctionName(),
      args : [],
      normalized_args: [],
      filename: PHP.getFilename(),
      lineno: PHP.getLineNo(),
      context: 'command',
      type: 'command_execution',
      request_uri: PHP.getServerEnv('REQUEST_URI'),
      remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
      query_string: PHP.getServerEnv('QUERY_STRING'),
      document_root: PHP.getServerEnv('DOCUMENT_ROOT')
    };

    var zendParseParameters = PHP.getZendParseParameters(3, fmt, cmd, cmdLen, descriptorspec, pipes, cwd, cwdLen, environment, otherOptions);
    var fmt = Memory.allocUtf8String('saz/|s!a!a!');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);
    var descriptorspec = Memory.alloc(Process.pointerSize);
    var pipes = Memory.alloc(Process.pointerSize);
    var cwd = Memory.alloc(Process.pointerSize);
    var cwdLen = Memory.alloc(Process.pointerSize);
    var environment = Memory.alloc(Process.pointerSize);
    var otherOptions  = Memory.alloc(Process.pointerSize);

    zendParseParameters(3, fmt, cmd, cmdLen, descriptorspec, pipes, cwd, cwdLen, environment, otherOptions);
    message.args.push(Memory.readCString(Memory.readPointer(cmd)))

    send(message);
  },
  // onLeave: function (retval) {
  // }
}

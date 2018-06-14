{
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

    var zendParseParameters = PHP.getZendParseParameters(2, fmt, cmd, cmdLen, mode, modeLen);
    var fmt = Memory.allocUtf8String('ps');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);
    var mode = Memory.alloc(Process.pointerSize);
    var modeLen = Memory.alloc(Process.pointerSize);

    zendParseParameters(2, fmt, cmd, cmdLen, mode, modeLen);
    message.args.push(Memory.readCString(Memory.readPointer(cmd)))
    message.args.push(Memory.readCString(Memory.readPointer(mode)))

    send(message);
  }
}
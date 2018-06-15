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

    var zendParseParameters = PHP.getZendParseParameters(1, fmt, cmd, cmdLen);
    var fmt = Memory.allocUtf8String('s');
    var cmd = Memory.alloc(Process.pointerSize);
    var cmdLen = Memory.alloc(Process.pointerSize);

    zendParseParameters(1, fmt, cmd, cmdLen);
    message.args.push(Memory.readCString(Memory.readPointer(cmd)));

    send(message);
  }
}

{
  onEnter: function (args) {
    var message = {
      function: PHP.getFunctionName(),
      args : [],
      normalized_args: [],
      filename: PHP.getFilename(),
      lineno: PHP.getLineNo(),
      context: 'url',
      type: 'network_access',
      request_uri: PHP.getServerEnv('REQUEST_URI'),
      remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
      query_string: PHP.getServerEnv('QUERY_STRING'),
      document_root: PHP.getServerEnv('DOCUMENT_ROOT')
    };

    var zendParseParameters = PHP.getZendParseParameters(3, fmt, socket, addr, addrlen, port);
    var fmt = Memory.allocUtf8String('rs|l');
    var socket = Memory.alloc(Process.pointerSize);
    var addr = Memory.alloc(Process.pointerSize);
    var addrlen = Memory.alloc(Process.pointerSize);
    var port = Memory.alloc(Process.pointerSize);

    zendParseParameters(3, fmt, socket, addr, addrlen, port);
    message.args.push(Memory.readCString(Memory.readPointer(addr)));
    message.args.push(Memory.readUInt(port));
    message.normalized_args.push(Memory.readCString(Memory.readPointer(addr)) + ":" + Memory.readUInt(port));

    send(message);
  }
}

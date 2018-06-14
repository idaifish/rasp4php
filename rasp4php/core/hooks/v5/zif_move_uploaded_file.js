{
  onEnter: function (args) {
    var message = {
      function: PHP.getFunctionName(),
      args : [],
      normalized_args: [],
      filename: PHP.getFilename(),
      lineno: PHP.getLineNo(),
      context: 'file',
      type: 'file_upload',
      request_uri: PHP.getServerEnv('REQUEST_URI'),
      remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
      query_string: PHP.getServerEnv('QUERY_STRING'),
      document_root: PHP.getServerEnv('DOCUMENT_ROOT')
    };

    var zendParseParameters = PHP.getZendParseParameters(2, fmt, src, srclen, dest, destlen);
    var fmt = Memory.allocUtf8String('sp');
    var src = Memory.alloc(Process.pointerSize);
    var srclen = Memory.alloc(Process.pointerSize);
    var dest = Memory.alloc(Process.pointerSize);
    var destlen = Memory.alloc(Process.pointerSize);

    zendParseParameters(2, fmt, src, srclen, dest, destlen);
    message.args.push(Memory.readCString(Memory.readPointer(src)));
    message.args.push(Memory.readCString(Memory.readPointer(dest)));

    send(message);
  }
}
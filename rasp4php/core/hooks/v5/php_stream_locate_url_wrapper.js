{
  onEnter: function (args) {
    var message = {
      function: PHP.getFunctionName(),
      args : [],
      normalized_args: [],
      filename: PHP.getFilename(),
      lineno: PHP.getLineNo(),
      context: 'file',
      type: 'file_operation',
      request_uri: PHP.getServerEnv('REQUEST_URI'),
      remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
      query_string: PHP.getServerEnv('QUERY_STRING'),
      document_root: PHP.getServerEnv('DOCUMENT_ROOT')
    };

    var openedFilename = Memory.readCString(args[0]);
    message.args.push(openedFilename);
    message.normalized_args.push(PHP.getRealPath(args[0]));

    if (message.function === 'main') {
      message.function = 'include_or_require';
    }

    if (message.filename !== '[no active file]') {
      send(message);
    }
  }
}
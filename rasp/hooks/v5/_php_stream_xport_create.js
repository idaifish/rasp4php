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

    var remoteSocket = Memory.readCString(args[0])
    message.args.push(remoteSocket);
    if (remoteSocket.indexOf("://") === -1) {
      // no transport is specified
      message.normalized_args.push("tcp://" + remoteSocket);
    } else {
      message.normalized_args.push(remoteSocket);
    }

    send(message);
  }
}
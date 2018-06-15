{
  onEnter: function (args) {
    var message = {
      function: "include_or_require",
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

    var requiredFilename = Memory.readCString(args[0]);
    message.args.push(requiredFilename);

    this.message = message;
  },
  onLeave: function (retval) {
      if (parseInt(retval)) {
        this.message.normalized_args.push(Memory.readCString(ptr(retval).add(24)));
        if (this.message.filename !== '[no active file]') {
          send(this.message);
        }
      }
  }
}
{
  onEnter: function (args) {
    var CURLOPT_URL = 10002;

    if (args[1].toInt32() === CURLOPT_URL) {
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

      var url = Memory.readCString(args[2]);
      message.args.push(url);
      if (url.indexOf("://") === -1) {
        message.normalized_args.push("//" + url);
      }

      send(message);
    }
  }
}

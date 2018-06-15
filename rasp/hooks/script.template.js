{
  onEnter: function (args) {
    /*
     Declare context and type.
        Context: code, command, sql, file, url, var, xxe
        Type:
          - file_operation
          - code_execution
          - command_execution
          - network_access
          - database_query
          - info_leak
          - deserialization
     */
     var message = {
       function: PHP.getFunctionName(),
       args : [],
       normalized_args: [],
       filename: PHP.getFilename(),
       lineno: -1,
       context: '',
       type: '',
       request_uri: PHP.getServerEnv('REQUEST_URI'),
       remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
       query_string: PHP.getServerEnv('QUERY_STRING'),
       document_root: PHP.getServerEnv('DOCUMENT_ROOT')
     };

    // Function body here.

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}

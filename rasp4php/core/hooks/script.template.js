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
    message.context = '';
    message.type = '';

    // Function body here.

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}

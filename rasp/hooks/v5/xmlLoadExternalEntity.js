{
  /*
    xmlParserInputPtr	xmlLoadExternalEntity	(const char * URL, const char * ID, xmlParserCtxtPtr ctxt)
   */
  onEnter: function (args) {
    var message = {
      function: PHP.getFunctionName(),
      args : [],
      normalized_args: [],
      filename: PHP.getFilename(),
      lineno: PHP.getLineNo(),
      context: 'xxe',
      type: 'xml_external_entity',
      request_uri: PHP.getServerEnv('REQUEST_URI'),
      remote_addr: PHP.getServerEnv('REMOTE_ADDR'),
      query_string: PHP.getServerEnv('QUERY_STRING'),
      document_root: PHP.getServerEnv('DOCUMENT_ROOT')
    };

    message.args.push(Memory.readCString(args[0]));
    message.args.push(Memory.readCString(args[1]));

    send(message);
  }
}

{
  /*
    xmlParserInputPtr	xmlLoadExternalEntity	(const char * URL, const char * ID, xmlParserCtxtPtr ctxt)
   */
  onEnter: function (args) {
    var message = {
        function: "xml_load_external_entity",
        args : [],
        filename: "",
        lineno: -1,
        context: 'xxe',
        type: 'xml_external_entity'
    };

    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    message.filename = Memory.readCString(ptr(getFilename()));
    message.lineno = getLineno();

    message.args.push(Memory.readCString(args[0]));
    message.args.push(Memory.readCString(args[1]));

    send(message);
  },
  /* onLeave: function (retval) {
      // Omit onLeave Callback
  } */
}

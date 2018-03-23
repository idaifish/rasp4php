{
    /*
     * zend_op_array* compile_string(zval *source_string, char *filename);
     *  - eval()
     *  - assert()
     *  - create_function
     *
     */
    onEnter: function (args) {
      /*
       * args[0]:
       *     struct _zend_string {
       *       zend_refcounted_h gc;
       *       zend_ulong        h;                // hash value
       *       size_t            len;
       *       char              val[1];
       *     };
       *
       * args[1]:
       *     char *filename
       */
       var message = {
             function: "eval",
             args : [],
             filename: '',
             lineno: -1
           };
        var evalStringOffset = 24
        var evalString = Memory.readCString(Memory.readPointer(args[0]).add(evalStringOffset));
        var evalFile = Memory.readCString(args[1]);

        message.args.push(evalString);
        message.filename = evalFile.split('(')[0];
        message.lineno = parseInt(evalFile.split('(')[1].split(')')[0], 10);

        if (evalFile.includes("assert code")) {
          message.function = "assert";
        } else if (evalFile.includes("runtime-created function")) {
          message.function = "create_function";
        }

        send(message);
    },

    // onLeave: function (retval) {
    // }
}

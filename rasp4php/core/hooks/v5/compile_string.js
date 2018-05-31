{
    /*
     * zend_op_array* compile_string(zval *source_string, char *filename);
     *  - eval()
     *  - assert()
     *  - create_function
     */
    onEnter: function (args) {
        var message = {
            function: "eval",
            args : [],
            filename: '',
            lineno: -1,
            context: 'code',
            type: 'code_execution'
        };
        var evalStringOffset = 0
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

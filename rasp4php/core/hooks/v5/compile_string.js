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

        var sapi_getenv_addr = Module.findExportByName(null, 'sapi_getenv');
        var sapi_getenv = new NativeFunction(sapi_getenv_addr, 'pointer', ['pointer', 'int']);
        var envArray = ['SERVER_ADDR', 'SERVER_NAME', 'QUERY_STRING', 'DOCUMENT_ROOT', 'REMOTE_ADDR', 'REQUEST_URI'];
        var getenv = function (env) {
            var envName= Memory.allocUtf8String(env);
            var envValue = sapi_getenv(envName, env.length);
            return Memory.readCString(envValue);
        }
        message.query_string = getenv("QUERY_STRING");
        message.remote_addr = getenv("REMOTE_ADDR");
        message.request_uri = getenv("REQUEST_URI");

        send(message);
    },

    // onLeave: function (retval) {
    // }
}

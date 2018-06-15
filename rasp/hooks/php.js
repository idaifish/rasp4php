/*  PHP API */
PHP = {
  getFilename: function () {
    var getFilenameAddr = Module.findExportByName(null, 'zend_get_executed_filename');
    var _getFilename = new NativeFunction(getFilenameAddr, 'pointer', []);
    var filename = Memory.readCString(ptr(_getFilename()));

    if (filename.indexOf('(') !== -1) {
      return filename.substring(0, filename.indexOf('('));
    }

    return filename;
  },
  getLineNo: function () {
    var getLinenoAddr = Module.findExportByName(null, 'zend_get_executed_lineno');
    var _getLineno = new NativeFunction(getLinenoAddr, 'uint32', []);

    return _getLineno();
  },
  getServerEnv: function (env) {
    // $_SERVER
    var sapi_getenv_addr = Module.findExportByName(null, 'sapi_getenv');
    var sapi_getenv = new NativeFunction(sapi_getenv_addr, 'pointer', ['pointer', 'int']);
    var envName= Memory.allocUtf8String(env);
    var envValue = sapi_getenv(envName, env.length);

    return Memory.readCString(envValue);
  },
  getFunctionName: function () {
    var getFunctionAddr = Module.findExportByName(null, 'get_active_function_name');
    var _getFunction = new NativeFunction(getFunctionAddr, 'pointer', []);
    var getClassNameAddr = Module.findExportByName(null, 'get_active_class_name');
    var _getClassName = new NativeFunction(getClassNameAddr, 'pointer', ['pointer']);
    var spacePointer = Memory.alloc(Process.pointerSize);

    var functionName = Memory.readCString(ptr(_getFunction()));
    var className = Memory.readCString(ptr(_getClassName(spacePointer)));

    if (className !== '') {
      return className + '::' + functionName;
    } else {
      return functionName;
    }
  },
  getRealPath: function (pathPointer) {
    var tsrmRealPathAddr = Module.findExportByName(null, 'tsrm_realpath');
    var tsrmRealPath = new NativeFunction(tsrmRealPathAddr, 'pointer', ['pointer', 'pointer']);
    var realpathPointer = Memory.alloc(100);
    var path = Memory.readCString(pathPointer);

    if (path.startsWith('file://')) {
        var newPathPointer = Memory.allocUtf8String(path.substring(7));
        tsrmRealPath(newPathPointer, realpathPointer);
    } else {
        tsrmRealPath(pathPointer, realpathPointer);
    }

    return Memory.readCString(ptr(realpathPointer));
  },
  getZendParseParameters: function (parameters) {
    var params = [];
    for (var i = 0; i < arguments.length; i++) {
      if (typeof arguments[i] === 'number') {
        params.push('int');
      } else {
        params.push('pointer');
      }
    }

    var zendParseParametersAddr = Module.findExportByName(null, 'zend_parse_parameters');
    var zendParseParameters = new NativeFunction(zendParseParametersAddr, 'int', params);

    return zendParseParameters;
  }
}
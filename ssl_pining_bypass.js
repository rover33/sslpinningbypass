if (ObjC.available) {
    console.log("[*] Starting iOS SSL Pinning Bypass");

    // Hook SecTrustEvaluate (iOS Security Framework, used in URLSession)
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
                console.log("[*] Hooking SecTrustEvaluate");
                Memory.writePointer(result, 1); // kSecTrustResultUnspecified
                return 0; // Success
            }, 'int', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluate hooked");
        } else {
            console.log("[-] SecTrustEvaluate not found");
        }
    } catch (e) {
        console.log("[-] Error hooking SecTrustEvaluate: " + e);
    }

    // Hook SecTrustEvaluateWithError (iOS 12+, modern apps)
    try {
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
                console.log("[*] Hooking SecTrustEvaluateWithError");
                Memory.writePointer(error, NULL); // No error
                return true; // Trust is valid
            }, 'bool', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluateWithError hooked");
        } else {
            console.log("[-] SecTrustEvaluateWithError not found");
        }
    } catch (e) {
        console.log("[-] Error hooking SecTrustEvaluateWithError: " + e);
    }

    // Hook SSLSetSessionOption (for low-level SSL)
    try {
        var SSLSetSessionOption = Module.findExportByName("Security", "SSLSetSessionOption");
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (session, option, value) {
                console.log("[*] Hooking SSLSetSessionOption");
                return 0; // Success, bypass restrictions
            }, 'int', ['pointer', 'int', 'bool']));
            console.log("[+] SSLSetSessionOption hooked");
        } else {
            console.log("[-] SSLSetSessionOption not found");
        }
    } catch (e) {
        console.log("[-] Error hooking SSLSetSessionOption: " + e);
    }

    console.log("[*] iOS SSL Pinning Bypass Complete");
} else {
    console.log("[-] Objective-C runtime not available");
}

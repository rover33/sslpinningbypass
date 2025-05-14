Java.perform(function () {
    console.log("[*] Starting SSL Pinning Bypass");

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
                return true; // Trust is valid
            }, 'bool', ['pointer', 'pointer']));
            console.log("[+] SecTrustEvaluateWithError hooked");
        }
    } catch (e) {
        console.log("[-] Error hooking SecTrustEvaluateWithError: " + e);
    }

    // Hook SSLSetSessionOption (for apps using low-level SSL)
    try {
        var SSLSetSessionOption = Module.findExportByName("Security", "SSLSetSessionOption");
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (session, option, value) {
                console.log("[*] Hooking SSLSetSessionOption");
                return 0; // Success, bypass restrictions
            }, 'int', ['pointer', 'int', 'bool']));
            console.log("[+] SSLSetSessionOption hooked");
        }
    } catch (e) {
        console.log("[-] Error hooking SSLSetSessionOption: " + e);
    }

    // Generic hook for custom pinning (e.g., TrustKit, BoringSSL)
    try {
        var ssl_verify = ["SSL_CTX_set_verify", "SSL_CTX_set_custom_verify"];
        ssl_verify.forEach(function (func) {
            var addr = Module.findExportByName(null, func);
            if (addr) {
                Interceptor.replace(addr, new NativeCallback(function (ssl, mode, callback) {
                    console.log("[*] Hooking " + func);
                    return; // Bypass verification
                }, 'void', ['pointer', 'int', 'pointer']));
                console.log("[+] " + func + " hooked");
            }
        });
    } catch (e) {
        console.log("[-] Error hooking custom SSL verify: " + e);
    }

    console.log("[*] SSL Pinning Bypass Complete");
});

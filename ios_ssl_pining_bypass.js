if (ObjC.available) {
    console.log("[*] Starting iOS SSL Pinning Bypass");

    // Bypass ptrace anti-debugging
    try {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (ptrace) {
            Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
                console.log("[*] Bypassing ptrace");
                if (request === 31) { // PT_DENY_ATTACH
                    return -1; // Fail the attach attempt
                }
                return 0;
            }, 'int', ['int', 'int', 'pointer', 'pointer']));
            console.log("[+] ptrace hooked");
        } else {
            console.log("[-] ptrace not found");
        }
    } catch (e) {
        console.log("[-] Error hooking ptrace: " + e);
    }

    // Bypass sysctl (jailbreak/Frida detection)
    try {
        var sysctl = Module.findExportByName(null, "sysctl");
        if (sysctl) {
            Interceptor.replace(sysctl, new NativeCallback(function(name, namelen, oldp, oldlenp, newp, newlen) {
                console.log("[*] Bypassing sysctl");
                return 0; // Prevent detection of Frida or jailbreak
            }, 'int', ['pointer', 'uint', 'pointer', 'pointer', 'pointer', 'uint']));
            console.log("[+] sysctl hooked");
        } else {
            console.log("[-] sysctl not found");
        }
    } catch (e) {
        console.log("[-] Error hooking sysctl: " + e);
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

    console.log("[*] iOS SSL Pinning Bypass Complete");
} else {
    console.log("[-] Objective-C runtime not available");
}

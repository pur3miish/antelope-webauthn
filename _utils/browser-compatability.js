export default function assertEnvironmentCompatibility() {
    const isBrowser = typeof navigator !== "undefined";
    const isNode = typeof process !== "undefined" && !!process.versions?.node;
    function isDenoEnv(obj) {
        return typeof obj === "object" && obj !== null && "Deno" in obj;
    }
    const isDeno = isDenoEnv(globalThis);
    // For Node and Deno, we assume developer is using the correct runtime
    if (isNode || isDeno) {
        return; // compatible by design
    }
    // If not a browser, node, or deno — reject
    if (!isBrowser) {
        throw new Error("Unknown environment: not a browser, Node.js, or Deno.");
    }
    // === Browser compatibility check ===
    const ua = navigator.userAgent;
    const throwUnsupported = (browser, current, required) => {
        window.alert(`${browser} version ${current} is not supported.\n` +
            `Please update your browser or switch to a modern, compatible browser.\n` +
            `Minimum required version is ${required}.`);
        throw new Error(`${browser} version ${current} is not supported. Please upgrade to at least version ${required}.`);
    };
    // Safari (desktop or iOS)
    const safariMatch = ua.match(/Version\/([\d.]+).*Safari/);
    const isSafari = safariMatch &&
        ua.includes("Safari") &&
        !ua.includes("Chrome") &&
        !ua.includes("Chromium");
    if (isSafari) {
        const version = parseFloat(safariMatch[1]);
        if (version < 18.5)
            throwUnsupported("Safari", version.toString(), "18.5");
        return;
    }
    // iOS Chrome/Firefox (still use Safari engine)
    const isIOS = /iP(hone|ad|od)/.test(ua);
    if (isIOS) {
        const iosSafariMatch = ua.match(/OS (\d+)_/);
        if (iosSafariMatch) {
            const iosVersion = parseInt(iosSafariMatch[1]);
            if (iosVersion < 16)
                throwUnsupported("iOS Safari", iosVersion.toString(), "16");
        }
        else {
            throw new Error("Unable to determine iOS version.");
        }
        return;
    }
    // Android Chrome
    const androidMatch = ua.match(/Android\s[\d.]+;\s([^)]+)\)\s+Chrome\/([\d.]+)/);
    if (androidMatch) {
        const chromeVersion = parseFloat(androidMatch[2]);
        if (chromeVersion < 113)
            throwUnsupported("Android Chrome", chromeVersion.toString(), "113");
        return;
    }
    // Chrome (desktop)
    const chromeMatch = ua.match(/Chrome\/([\d.]+)/);
    if (chromeMatch && ua.includes("Chrome") && !ua.includes("Edg")) {
        const version = parseFloat(chromeMatch[1]);
        if (version < 113)
            throwUnsupported("Chrome", version.toString(), "113");
        return;
    }
    // Firefox (desktop or Android)
    const firefoxMatch = ua.match(/Firefox\/([\d.]+)/);
    if (firefoxMatch) {
        const version = parseFloat(firefoxMatch[1]);
        if (version < 110)
            throwUnsupported("Firefox", version.toString(), "110");
        return;
    }
    // Edge
    const edgeMatch = ua.match(/Edg\/([\d.]+)/);
    if (edgeMatch) {
        const version = parseFloat(edgeMatch[1]);
        if (version < 113)
            throwUnsupported("Edge", version.toString(), "113");
        return;
    }
    throw new Error("Unsupported or unknown browser. Please update or switch to a compliant modern browser.");
}

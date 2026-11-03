// Native macOS window for Private Assistant: a WKWebView that only shows the local server.
// Built by scripts/install.py with swiftc; the address is read from Resources/url.txt.
import Cocoa
import WebKit
import Security
import LocalAuthentication

let address: URL = {
    let res = Bundle.main.resourceURL?.appendingPathComponent("url.txt")
    let text = (res.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "http://127.0.0.1:8765/").trimmingCharacters(in: .whitespacesAndNewlines)
    return URL(string: text) ?? URL(string: "http://127.0.0.1:8765/")!
}()

func isLocal(_ u: URL?) -> Bool {
    guard let u = u, let h = u.host else { return u?.scheme == "about" || u?.scheme == "blob" }
    return h == address.host && u.port == address.port
}

// Saved sign-in: email and password live in this Mac's Keychain, and reading them needs Touch ID or your Mac password.
enum Vault {
    static let service = "local.privhybrid.app"
    static func query(_ extra: [String: Any] = [:]) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        extra.forEach { q[$0.key] = $0.value }
        return q
    }
    static var exists: Bool { SecItemCopyMatching(query([kSecReturnAttributes as String: true]) as CFDictionary, nil) == errSecSuccess }
    static func save(_ email: String, _ pw: String) {
        SecItemDelete(query() as CFDictionary)
        SecItemAdd(query([kSecAttrAccount as String: email, kSecValueData as String: Data(pw.utf8),
                          kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]) as CFDictionary, nil)
    }
    static func savedEmail() -> String? {
        var out: CFTypeRef?
        guard SecItemCopyMatching(query([kSecReturnAttributes as String: true]) as CFDictionary, &out) == errSecSuccess,
              let d = out as? [String: Any] else { return nil }
        return d[kSecAttrAccount as String] as? String
    }
    static func forget() { SecItemDelete(query() as CFDictionary) }
    static func read() -> (String, String)? {
        var out: CFTypeRef?
        let q = query([kSecReturnAttributes as String: true, kSecReturnData as String: true])
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? [String: Any],
              let email = d[kSecAttrAccount as String] as? String, let data = d[kSecValueData as String] as? Data,
              let pw = String(data: data, encoding: .utf8) else { return nil }
        return (email, pw)
    }
    static func unlock(_ why: String, _ done: @escaping (Bool) -> Void) {
        let c = LAContext()
        guard c.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { done(false); return }
        c.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: why) { ok, _ in DispatchQueue.main.async { done(ok) } }
    }
}

let hookJS = """
(function(){
  var f = document.getElementById('loginForm'); if (!f) return;
  var post = function(m){ window.webkit.messageHandlers.ph.postMessage(m); };
  f.addEventListener('submit', function(){ post({t:'submit', email: document.getElementById('email').value, pw: document.getElementById('pw').value}); }, true);
  var seen = false;
  setInterval(function(){
    var l = document.getElementById('login');
    if (!l) return;
    if (l.hidden) { if (!seen) { seen = true; post({t:'in'}); } return; }
    seen = false;
    if (window.__phHas && !document.getElementById('phKey')) {
      var b = document.createElement('button'); b.type = 'button'; b.id = 'phKey'; b.textContent = 'Sign in with saved login (Touch ID)';
      b.className = 'secondary'; b.style.marginTop = '10px';
      b.onclick = function(){ post({t:'fill'}); };
      f.appendChild(b);
    }
  }, 600);
})();
"""

final class Delegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate, WKScriptMessageHandler {
    var pending: (String, String)?

    func userContentController(_ u: WKUserContentController, didReceive m: WKScriptMessage) {
        guard isLocal(m.frameInfo.request.url), let d = m.body as? [String: Any], let t = d["t"] as? String else { return }
        switch t {
        case "submit":
            if let e = d["email"] as? String, let p = d["pw"] as? String { pending = (e, p) }
        case "in":
            guard let (e, p) = pending else { return }
            pending = nil
            if Vault.savedEmail() == e { Vault.save(e, p); return }
            let a = NSAlert()
            a.messageText = "Save this login on this Mac?"
            a.informativeText = "Your email and password are stored in your Mac's Keychain. Using them later needs Touch ID or your Mac password. Nothing is sent anywhere."
            a.addButton(withTitle: "Save"); a.addButton(withTitle: "Not now")
            a.beginSheetModal(for: window) { r in
                if r == .alertFirstButtonReturn { Vault.save(e, p); self.web.evaluateJavaScript("window.__phHas = true") }
            }
        case "fill":
            Vault.unlock("Sign in to Private Assistant") { ok in
                guard ok, let (e, p) = Vault.read() else { return }
                let js = "(function(){var s=function(i,v){var x=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;x.call(i,v);i.dispatchEvent(new Event('input',{bubbles:true}));};"
                    + "s(document.getElementById('email'),\(Self.lit(e)));s(document.getElementById('pw'),\(Self.lit(p)));document.getElementById('loginForm').requestSubmit();})()"
                self.web.evaluateJavaScript(js)
            }
        default: break
        }
    }

    static func lit(_ s: String) -> String {
        let d = try? JSONSerialization.data(withJSONObject: [s], options: [])
        let t = String(data: d ?? Data("[\"\"]".utf8), encoding: .utf8)!
        return String(t.dropFirst().dropLast())
    }

    @objc func forgetLogin(_ s: Any?) {
        Vault.forget(); web.evaluateJavaScript("window.__phHas = false; var k=document.getElementById('phKey'); if(k) k.remove();")
    }

    var window: NSWindow!
    var web: WKWebView!

    func applicationDidFinishLaunching(_ n: Notification) {
        let cfg = WKWebViewConfiguration()
        cfg.userContentController.add(self, name: "ph")
        cfg.userContentController.addUserScript(WKUserScript(source: "window.__phHas = \(Vault.exists);", injectionTime: .atDocumentStart, forMainFrameOnly: true))
        cfg.userContentController.addUserScript(WKUserScript(source: hookJS, injectionTime: .atDocumentEnd, forMainFrameOnly: true))
        web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = self
        web.uiDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1240, height: 860),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Private Assistant"
        window.contentView = web
        window.delegate = self
        window.setFrameAutosaveName("PrivateAssistantMain")
        if !window.setFrameUsingName("PrivateAssistantMain") { window.center() }
        window.makeKeyAndOrderFront(nil)
        web.load(URLRequest(url: address))
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }

    // Only the local server is shown here; any other link opens in the default browser.
    func webView(_ w: WKWebView, decidePolicyFor a: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if isLocal(a.request.url) { decisionHandler(.allow); return }
        if let u = a.request.url, ["http", "https", "mailto"].contains(u.scheme ?? "") { NSWorkspace.shared.open(u) }
        decisionHandler(.cancel)
    }

    func webView(_ w: WKWebView, createWebViewWith c: WKWebViewConfiguration, for a: WKNavigationAction, windowFeatures f: WKWindowFeatures) -> WKWebView? {
        if let u = a.request.url, !isLocal(u) { NSWorkspace.shared.open(u) } else if let u = a.request.url { w.load(URLRequest(url: u)) }
        return nil
    }

    // The microphone button: allowed for the local page only.
    @available(macOS 12.0, *)
    func webView(_ w: WKWebView, requestMediaCapturePermissionFor o: WKSecurityOrigin, initiatedByFrame f: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        decisionHandler(o.host == address.host ? .grant : .deny)
    }

    // File upload dialog.
    func webView(_ w: WKWebView, runOpenPanelWith p: WKOpenPanelParameters, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = p.allowsMultipleSelection
        panel.canChooseDirectories = p.allowsDirectories
        panel.beginSheetModal(for: window) { completionHandler($0 == .OK ? panel.urls : nil) }
    }

    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = m; a.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = m; a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        a.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn) }
    }

    // Server not up yet (it starts at login): try again shortly instead of a blank window.
    func webView(_ w: WKWebView, didFailProvisionalNavigation n: WKNavigation!, withError e: Error) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { w.load(URLRequest(url: address)) }
    }

    // The server's certificate is signed by this install's own CA (Resources/ca.crt); trust that CA for this one host and nothing else.
    func webView(_ w: WKWebView, didReceive c: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let ps = c.protectionSpace
        guard ps.authenticationMethod == NSURLAuthenticationMethodServerTrust, ps.host == address.host, let trust = ps.serverTrust,
              let url = Bundle.main.resourceURL?.appendingPathComponent("ca.crt"), let pem = try? String(contentsOf: url, encoding: .utf8) else {
            completionHandler(.performDefaultHandling, nil); return
        }
        let b64 = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: b64), let ca = SecCertificateCreateWithData(nil, der as CFData) else {
            completionHandler(.performDefaultHandling, nil); return
        }
        SecTrustSetAnchorCertificates(trust, [ca] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var err: CFError?
        if SecTrustEvaluateWithError(trust, &err) { completionHandler(.useCredential, URLCredential(trust: trust)) }
        else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }

    @objc func reload(_ s: Any?) { web.reload() }
}

let app = NSApplication.shared
let delegate = Delegate()
app.delegate = delegate
app.setActivationPolicy(.regular)

let main = NSMenu()
let appItem = NSMenuItem(); main.addItem(appItem)
let appMenu = NSMenu(); appItem.submenu = appMenu
appMenu.addItem(withTitle: "Hide Private Assistant", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
let fg = NSMenuItem(title: "Forget Saved Login", action: #selector(Delegate.forgetLogin(_:)), keyEquivalent: ""); fg.target = delegate; appMenu.addItem(fg)
appMenu.addItem(withTitle: "Quit Private Assistant", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
let editItem = NSMenuItem(); main.addItem(editItem)
let edit = NSMenu(title: "Edit"); editItem.submenu = edit
edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
edit.addItem(.separator())
edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
let viewItem = NSMenuItem(); main.addItem(viewItem)
let view = NSMenu(title: "View"); viewItem.submenu = view
let rl = NSMenuItem(title: "Reload", action: #selector(Delegate.reload(_:)), keyEquivalent: "r"); rl.target = delegate; view.addItem(rl)
app.mainMenu = main
app.run()

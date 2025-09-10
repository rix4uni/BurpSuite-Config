from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList

class BurpExtender(IBurpExtender, IContextMenuFactory):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Send to Intruder from HTTP History")
        callbacks.registerContextMenuFactory(self)
        print("[+] Extension Loaded: Send to Intruder from HTTP History")
        return

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        context = invocation.getInvocationContext()
        print("[*] Invocation context:", context)

        # Allow the menu in any context (remove restrictive context check for testing)
        menu_item = JMenuItem("Send to Intruder", actionPerformed=lambda x, inv=invocation: self.send_to_intruder(inv))
        menu_list.add(menu_item)
        return menu_list

    def send_to_intruder(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages is None:
            print("[!] No selected messages.")
            return

        for message in messages:
            request = message.getRequest()
            http_service = message.getHttpService()
            # Add to Intruder
            self._callbacks.sendToIntruder(
                http_service.getHost(),
                http_service.getPort(),
                http_service.getProtocol() == "https",
                request,
                None
            )
            print("[+] Sent request to Intruder: " + http_service.getHost())

        print("[+] Finished sending selected HTTP History items to Intruder.")

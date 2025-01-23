from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from java.awt.event import ActionListener
from javax.swing import JMenuItem, JOptionPane
import os
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Copy Raw Request to File")
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
    
    def createMenuItems(self, invocation):
        menuItem = JMenuItem("Copy Raw Request to File")
        menuItem.addActionListener(self.MenuItemListener(invocation, self.callbacks))
        return [menuItem]
    
    class MenuItemListener(ActionListener):
        def __init__(self, invocation, callbacks):
            self.invocation = invocation
            self.callbacks = callbacks
        
        def actionPerformed(self, event):
            selectedMessages = self.invocation.getSelectedMessages()
            if selectedMessages:
                for message in selectedMessages:
                    request = message.getRequest()
                    raw_request = self.callbacks.getHelpers().bytesToString(request)
                    self.saveRequestToFile(raw_request)
        
        def saveRequestToFile(self, request):
            # Ensure the directory exists
            dir_name = "BURP-REQUEST"
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
            
            # Determine the next available file name
            file_counter = 1
            files = os.listdir(dir_name)
            req_files = [f for f in files if re.match(r'req\d+\.txt', f)]
            if req_files:
                highest_num = max([int(re.findall(r'\d+', f)[0]) for f in req_files])
                file_counter = highest_num + 1
            
            file_name = os.path.join(dir_name, "req{}.txt".format(file_counter))
            
            # Write the request to the file in binary mode to preserve formatting
            with open(file_name, 'wb') as file:
                file.write(request.encode('utf-8'))

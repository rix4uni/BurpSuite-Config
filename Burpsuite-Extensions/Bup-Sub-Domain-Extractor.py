try:
    from burp import IBurpExtender
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import ITab
    from burp import IMessageEditor
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from burp import IHttpRequestResponse
    from java.io import PrintWriter, File, FileWriter
    from java.lang import Runnable
    from javax.swing import (JTable, JScrollPane, JSplitPane, JButton, JPanel,
                             JTextField, JLabel, SwingConstants, JDialog, Box,
                             JCheckBox, JMenuItem, SwingUtilities, JOptionPane,
                             BoxLayout, JPopupMenu, JFileChooser, JTextPane)

    from javax.swing.border import EmptyBorder
    from javax.swing.table import AbstractTableModel
    from java.awt import (GridLayout, BorderLayout, FlowLayout, Dimension, Point, Toolkit)
    from java.awt.datatransfer import (Clipboard, ClipboardOwner, StringSelection, Transferable)
    from java.net import URL, MalformedURLException
    from java.util import ArrayList

    from threading import Thread, Event

    from urlparse import urlparse

    import sys
    import os
    import socket
    import time
    import json

except ImportError as e:
    print e
    print "Failed to load dependencies. This issue maybe caused by using an unstable Jython version."

VERSION = '1.0'


class BurpExtender(IBurpExtender, ITab, ClipboardOwner):
    def registerExtenderCallbacks(self, callbacks):
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName('Subdomain Extractor')
        self._helpers = callbacks.getHelpers()

        self.scannerMenu = ScannerMenu(self)
        callbacks.registerContextMenuFactory(self.scannerMenu)
        print "Subdomain Extractor custom menu loaded"


class ScannerMenu(IContextMenuFactory):
    def __init__(self, scannerInstance):
        self.scannerInstance = scannerInstance

    def createMenuItems(self, contextMenuInvocation):
        self.contextMenuInvocation = contextMenuInvocation
        menuItems = ArrayList()

        sendToSSLScanner = JMenuItem(
            "Copy sub domains", actionPerformed=self.getSentUrl)
        sendToSSLScannerWithProtocol = JMenuItem(
            "Copy sub domains with protocol", actionPerformed=self.getSentUrlWithProtocol)
        
        menuItems.add(sendToSSLScanner)
        menuItems.add(sendToSSLScannerWithProtocol)
        
        return menuItems

    def getSentUrl(self, event):
        subs = set()
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages():
            if selectedMessage.getHttpService() is not None:
                try:
                    url = self.scannerInstance._helpers.analyzeRequest(
                        selectedMessage.getHttpService(),
                        selectedMessage.getRequest()).getUrl()
                    
                    subDomain = urlparse(url.toString()).hostname
                    if subDomain.startswith('www.'):
                        subDomain = subDomain[4:]
                    subs.add(subDomain)
                except:
                    self.scannerInstance._callbacks.issueAlert(
                        "Cannot get URL from the currently selected message " +
                        str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
            else:
                self.scannerInstance._callbacks.issueAlert(
                    "The selected request is null.")

        subs = sorted(subs)
        clipboardContent = "\n".join(subs)

        if clipboardContent:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(clipboardContent), None)

    def getSentUrlWithProtocol(self, event):
        subs = set()
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages():
            if selectedMessage.getHttpService() is not None:
                try:
                    url = self.scannerInstance._helpers.analyzeRequest(
                        selectedMessage.getHttpService(),
                        selectedMessage.getRequest()).getUrl()
                    
                    parsedUrl = urlparse(url.toString())
                    protocol = parsedUrl.scheme
                    hostname = parsedUrl.hostname
                    port = parsedUrl.port

                    if hostname.startswith('www.'):
                        hostname = hostname[4:]

                    # Construct the URL without the port if it's a standard one
                    if port in (80, 443) or port is None:
                        fullUrl = "{}://{}".format(protocol, hostname)
                    else:
                        fullUrl = "{}://{}:{}".format(protocol, hostname, port)
                    
                    subs.add(fullUrl)
                except:
                    self.scannerInstance._callbacks.issueAlert(
                        "Cannot get URL from the currently selected message " +
                        str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
            else:
                self.scannerInstance._callbacks.issueAlert(
                    "The selected request is null.")

        subs = sorted(subs)
        clipboardContent = "\n".join(subs)

        if clipboardContent:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(clipboardContent), None)

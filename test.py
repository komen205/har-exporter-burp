from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing import JButton, JPanel
from javax.swing.table import AbstractTableModel;
from threading import Lock
from burp import IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
import json
import base64
import string
import time
from javax.swing import JPanel, JButton, BoxLayout
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Custom logger")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        self.setupUI(callbacks)

        # Register as an HTTP listener and context menu factory
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)


        return
    
    def setupUI(self, callbacks):
        # Main split pane setup
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # Create a button
        button = JButton("Export HAR", actionPerformed=self.exportAllMessages)

        # Create a top-level panel
        topPanel = JPanel()
        topPanel.setLayout(BorderLayout())
        topPanel.add(button, BorderLayout.NORTH)
        topPanel.add(self._splitpane, BorderLayout.CENTER)

        # Customize and add the top-level panel to Burp's UI
        callbacks.customizeUiComponent(topPanel)

        # Add the top-level panel as the custom tab in Burp's UI
        callbacks.addSuiteTab(BurpTab(self, topPanel))
        
   
    def is_binary(self,data):
        # A simple heuristic to check if data is binary:
        # Check if most of the characters in the data are printable
        text_characters = ''.join(map(chr, range(32, 127)) + list('\n\r\t\b'))
        if not data:
            return False
        if isinstance(data, str):
            # If it's a string, we can check directly
            return bool(data.translate(None, text_characters))
        try:
            # Try to decode it as UTF-8
            data.decode('utf-8')
            return False
        except UnicodeDecodeError:
            return True
        

    def safe_base64_encode(self, data):
        if data is None:
            return ""

        # Convert the array.array to a byte string
        byte_data = bytearray(data)

        try:
            # Attempt to decode as UTF-8. If successful, return the decoded string
            decoded_string = byte_data.decode('utf-8')
            # Check if the decoded string contains mostly printable characters
            is_printable = all(char in string.printable or char.isspace() for char in decoded_string)
            return decoded_string if is_printable else base64.b64encode(byte_data).decode('utf-8')
        except UnicodeDecodeError:
            # If decoding fails, encode the data in Base64
            return base64.b64encode(byte_data).decode('utf-8')


    def exportAllMessages(self, event):
            # Logic to handle exporting all messages
            har_entries = []

            # Loop through all log entries and convert each to a HAR entry
            for i in range(self._log.size()):
                logEntry = self._log.get(i)
                message_info = logEntry._requestResponse
                timestamp = logEntry._timestamp
                har_entry = self.convertToHAR(message_info, timestamp)
                har_entries.append(har_entry)

            # Combine all HAR entries into a single HAR log
            har_log = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "Custom logger",
                        "version": "1.0"
                    },
                    "entries": har_entries
                }
            }

            # Save the HAR data to a file
            self.saveHAR(har_log, "exported_requests.har")

    
    def split_header(self,header):
        parts = header.split(":", 1)
        if len(parts) == 2:
            return {"name": parts[0].strip(), "value": parts[1].strip()}
        else:
            return {"name": header, "value": ""}
        
    def convertToHAR(self, message_info, timestamp):
        # Access the request and response
        request_bytes = message_info.getRequest()
        response_bytes = message_info.getResponse()


        # Analyze the request and response
        analyzed_request = self._helpers.analyzeRequest(message_info)
        analyzed_response = self._helpers.analyzeResponse(response_bytes) if response_bytes else None
        
        request_body_bytes = message_info.getRequest()[analyzed_request.getBodyOffset():]
        response_body_bytes = message_info.getResponse()[analyzed_response.getBodyOffset():] if response_bytes else None

        request_body_encoded = self.safe_base64_encode(request_body_bytes)
        response_body_encoded = self.safe_base64_encode(response_body_bytes)
        
        # Extract request details
        request_headers = analyzed_request.getHeaders()
        request_method = analyzed_request.getMethod()
        request_url = analyzed_request.getUrl()
        request_body = request_bytes[analyzed_request.getBodyOffset():].tostring() if request_bytes else ""

        # Extract response details
        response_headers = analyzed_response.getHeaders() if analyzed_response else []
        response_status = analyzed_response.getStatusCode() if analyzed_response else 0
        response_body = response_bytes[analyzed_response.getBodyOffset():].tostring() if response_bytes else ""
        response_mime_type = analyzed_response.getStatedMimeType() if analyzed_response else ""

        request_mime_type = ""
        for header in request_headers:
            if header.lower().startswith("content-type:"):
                # Split on ":", then take the second part and strip any leading/trailing whitespace
                request_mime_type = header.split(":", 1)[1].strip()
                break

        # Extract and format request headers
        request_headers_formatted = [self.split_header(str(header)) for header in request_headers[1:]]  # Exclude the start line

        # Extract and format response headers
        response_headers_formatted = [self.split_header(str(header)) for header in response_headers[1:]]  # Exclude the status line

        har_entry = {
            "startedDateTime": timestamp,  # You might want to format this timestamp
            "time": 0,  # You might need to calculate this
            "request": {
                "method": request_method,
                "url": str(request_url),
                "httpVersion": "HTTP/1.1",  # Burp doesn't expose version directly
                "cookies": [],  # Extract cookies if needed
            "headers": request_headers_formatted,
                "queryString": [],  # Extract query parameters if needed
                "postData": {
                    "mimeType": "application/json",  # You might need to determine this
                    "text": request_body_encoded
                },
                "headersSize": -1,  # Burp doesn't expose this directly
                "bodySize": len(request_body),
            },
            "response": {
                "status": response_status,
                "statusText": "",
                "httpVersion": "HTTP/1.1",  # Burp doesn't expose version directly
                "cookies": [],  # Extract cookies if needed
            "headers": response_headers_formatted,
                "content": {
                    "size": len(response_body_bytes) if response_body_bytes else 0,
                    "mimeType": "application/json",
                    "text": response_body_encoded
                },
                "redirectURL": "",  # Extract if needed
                "headersSize": -1,  # Burp doesn't expose this directly
                "bodySize": len(response_body),
            },
            "cache": {},  # Populate if needed
            "timings": {
                "send": 0,  # You might need to calculate this
                "wait": 0,  # You might need to calculate this
                "receive": 0,  # You might need to calculate this
            },
            "serverIPAddress": "",  # Extract if needed
            "connection": "",  # Extract if needed
        }

        return har_entry

    def saveHAR(self, har_data, filename):
        # Save the HAR data to a file
        with open(filename, 'w') as file:
            json.dump(har_data, file, indent=4)
            
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Logger"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return
        
        # Capture the current timestamp
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        # create a new log entry with the message details and timestamp
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), timestamp))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._url.toString()
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, timestamp):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._timestamp = timestamp  # Add timestamp attribute
        
class BurpTab(ITab):
    def __init__(self, extender, component):
        self._extender = extender
        self._component = component

    def getTabCaption(self):
        return "Custom Tab"

    def getUiComponent(self):
        return self._component
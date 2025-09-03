# -*- coding: utf-8 -*-

from burp import IBurpExtender, IScannerCheck, IScanIssue, IExtensionStateListener
import re
import array

class BurpExtender(IBurpExtender, IScannerCheck, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        print("Full Path Disclosure v.1.1 Extension Created By: Paweł Zdunek - AFINE Team")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("FPD Scanner")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)

        # Zmodyfikowany regex dla Windows paths – ignoruje d:\d\d (np. d:\12)
        self.windows_path_regex = re.compile(
            r'(?<![a-zA-Z0-9])([a-zA-Z]:\\(?:[a-zA-Z0-9_\-.\(\)\[\]{}#@!$^&~]+\\)+[a-zA-Z0-9_\-.\(\)\[\]{}#@!$^&~]+)(?!\\u[0-9a-fA-F]{4})'
        )

        directories = [
            "Applications", "System", "Volumes", "cores", "etc", "opt", "sbin", "usr",
            "Library", "Users", "bin", "dev", "home", "private", "tmp", "var"
        ]
        self.unix_path_regex = re.compile(
            r'(?<![a-zA-Z0-9])\/(?:' + '|'.join(directories) + r')\/[a-zA-Z0-9_\-.\(\)\[\]{}#@!$^&~]+(?:\/[a-zA-Z0-9_\-.\(\)\[\]{}#@!$^&~]+)*'
        )

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        response_body_offset = responseInfo.getBodyOffset()
        response_body = response[response_body_offset:].tostring()

        highlights = []
        found_paths = []

        # Szukamy ścieżek Windows
        for match in self.windows_path_regex.finditer(response_body):
            path = match.group(1)
            # Ignoruj regexy np. d:\d\d lub d:\d\d:\d\d
            if re.match(r'^[a-zA-Z]:\\[\\d:]+$', path):
                continue
            found_paths.append(path)
            start = match.start() + response_body_offset
            end = match.end() + response_body_offset
            highlights.append(array.array('i', [start, end]))

        # Szukamy ścieżek Unix
        for match in self.unix_path_regex.finditer(response_body):
            path = match.group(0)
            found_paths.append(path)
            start = match.start() + response_body_offset
            end = match.end() + response_body_offset
            highlights.append(array.array('i', [start, end]))

        if highlights:
            # Usuń duplikaty highlightów
            unique_highlights = [list(x) for x in set(tuple(h) for h in highlights)]
            highlight_arrays = [array.array('i', hl) for hl in unique_highlights]
            return [self.reportIssue(baseRequestResponse, highlight_arrays, found_paths)]
        return None

    def reportIssue(self, baseRequestResponse, highlights, paths):
        if paths:
            paths_text = "\n\nDisclosed paths:\n" + "\n".join("- `{}`".format(path) for path in set(paths))
        else:
            paths_text = ""

        detail_message = "Full Path Disclosure found in response." + paths_text

        marked_response = self._callbacks.applyMarkers(baseRequestResponse, None, highlights)
        return CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [marked_response],
            "Full Path Disclosure Detected",
            detail_message,
            "Information"
        )

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        return 0

    def extensionUnloaded(self):
        print("FPD Scanner extension unloaded.")


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

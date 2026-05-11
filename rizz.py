from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, IContextMenuFactory
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, BoxLayout, JTabbedPane, JTable, JSplitPane, JLabel, JComboBox
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Font, Color, Dimension
from java.awt.event import ActionListener
import json
import re
import difflib


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Rizz")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)
        self._stdout = callbacks.getStdout()

    def createNewInstance(self, controller, editable):
        return ApiSecuritySuiteTab(self, controller, editable)

    def createMenuItems(self, invocation):
        return None


class ApiSecuritySuiteTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._callbacks = extender._callbacks
        self._editable = editable
        self._currentMessage = None
        self._currentRequestInfo = None
        self._storedResponse = None
        self._storedRequestInfo = None

        self.HIDDEN_FIELDS = {
            "graphql_introspection": [
                "__typename", "__type", "__schema", "__field",
                "__inputValue", "__enumValue", "__directive"
            ],
            "debug_fields": [
                "debug", "isDebug", "is_debug", "_debug",
                "debugInfo", "debug_info", "internal", "_internal",
                "devMode", "dev_mode", "isDev", "is_dev"
            ],
            "admin_fields": [
                "isAdmin", "is_admin", "adminLevel", "admin_level",
                "role", "permissions", "isSuper", "isSuperAdmin",
                "privilege", "privileges"
            ],
            "system_fields": [
                "internalId", "internal_id", "systemId", "system_id",
                "serverId", "server_id", "databaseId", "database_id",
                "backendVersion", "backend_version", "apiVersion", "api_version"
            ],
            "security_fields": [
                "sessionToken", "session_token", "refreshToken", "refresh_token",
                "secretKey", "secret_key", "apiKey", "api_key",
                "encryptionKey", "encryption_key"
            ],
            "feature_flags": [
                "featureFlags", "feature_flags", "flags", "features",
                "betaFeatures", "beta_features", "experimentEnabled", "experiment_enabled"
            ]
        }

        
        self._panel = JPanel()
        self._panel.setLayout(BorderLayout())

        self._mainTabbedPane = JTabbedPane()

        
        analyzerPanel = self._createAnalyzerTab()
        self._mainTabbedPane.addTab("Response Analyzer", analyzerPanel)

        
        hiddenPanel = self._createHiddenFieldTab()
        self._mainTabbedPane.addTab("Hidden Field Detector", hiddenPanel)

        
        diffPanel = self._createDiffAnalyzerTab()
        self._mainTabbedPane.addTab("Response Diff", diffPanel)

        
        rawPanel = JPanel()
        rawPanel.setLayout(BorderLayout())
        self._rawResponseArea = JTextArea()
        self._rawResponseArea.setEditable(False)
        self._rawResponseArea.setFont(Font("Courier New", Font.PLAIN, 11))
        self._rawResponseArea.setBackground(Color(30, 30, 30))
        self._rawResponseArea.setForeground(Color(200, 200, 200))
        rawScrollPane = JScrollPane(self._rawResponseArea)
        rawPanel.add(rawScrollPane, BorderLayout.CENTER)
        self._mainTabbedPane.addTab("Raw Response", rawPanel)

        self._panel.add(self._mainTabbedPane, BorderLayout.CENTER)

    def _createAnalyzerTab(self):
        
        panel = JPanel()
        panel.setLayout(BorderLayout())

    
        tabbedPane = JTabbedPane()

    
        self._analysisArea = JTextArea()
        self._analysisArea.setEditable(False)
        self._analysisArea.setFont(Font("Courier New", Font.PLAIN, 10))
        self._analysisArea.setBackground(Color(30, 30, 30))
        self._analysisArea.setForeground(Color(76, 175, 80))
        analysisScroll = JScrollPane(self._analysisArea)
        tabbedPane.addTab("Analysis", analysisScroll)

        
        self._fieldsTable = JTable(DefaultTableModel(["Field Name", "Value (Preview)", "Sensitivity"], 0))
        self._fieldsTable.setBackground(Color(30, 30, 30))
        self._fieldsTable.setForeground(Color(200, 200, 200))
        fieldsScroll = JScrollPane(self._fieldsTable)
        tabbedPane.addTab("Extracted Fields", fieldsScroll)

        
        buttonPanel = JPanel()
        self._analyzeButton = JButton("Analyze Response")
        self._analyzeButton.addActionListener(self.onAnalyze)
        buttonPanel.add(self._analyzeButton)

        panel.add(tabbedPane, BorderLayout.CENTER)
        panel.add(buttonPanel, BorderLayout.SOUTH)

        return panel

    def _createHiddenFieldTab(self):
        
        panel = JPanel()
        panel.setLayout(BorderLayout())

        tabbedPane = JTabbedPane()

        self._hiddenTable = JTable(DefaultTableModel(["Field Name", "Category", "Risk Level", "Exploit Suggestion"], 0))
        self._hiddenTable.setBackground(Color(30, 30, 30))
        self._hiddenTable.setForeground(Color(200, 200, 200))
        self._hiddenTable.getColumnModel().getColumn(3).setPreferredWidth(300)
        hiddenScroll = JScrollPane(self._hiddenTable)
        tabbedPane.addTab("Hidden Fields", hiddenScroll)

        self._introspectionArea = JTextArea()
        self._introspectionArea.setEditable(False)
        self._introspectionArea.setFont(Font("Courier New", Font.PLAIN, 10))
        self._introspectionArea.setBackground(Color(30, 30, 30))
        self._introspectionArea.setForeground(Color(255, 193, 7))
        introspectionScroll = JScrollPane(self._introspectionArea)
        tabbedPane.addTab("GraphQL Analysis", introspectionScroll)

        self._payloadArea = JTextArea()
        self._payloadArea.setEditable(True)
        self._payloadArea.setFont(Font("Courier New", Font.PLAIN, 9))
        self._payloadArea.setBackground(Color(30, 30, 30))
        self._payloadArea.setForeground(Color(76, 175, 80))
        payloadScroll = JScrollPane(self._payloadArea)
        tabbedPane.addTab("Mutation Payloads", payloadScroll)

        buttonPanel = JPanel()
        self._detectButton = JButton("Detect Hidden Fields")
        self._detectButton.addActionListener(self.onDetect)
        self._generateButton = JButton("Generate Exploits")
        self._generateButton.addActionListener(self.onGenerateExploits)
        buttonPanel.add(self._detectButton)
        buttonPanel.add(self._generateButton)

        panel.add(tabbedPane, BorderLayout.CENTER)
        panel.add(buttonPanel, BorderLayout.SOUTH)

        return panel

    def _createDiffAnalyzerTab(self):
        
        panel = JPanel()
        panel.setLayout(BorderLayout())

        tabbedPane = JTabbedPane()

        
        self._currentArea = JTextArea()
        self._currentArea.setEditable(False)
        self._currentArea.setFont(Font("Courier New", Font.PLAIN, 9))
        self._currentArea.setBackground(Color(30, 30, 30))
        self._currentArea.setForeground(Color(200, 200, 200))
        currentScroll = JScrollPane(self._currentArea)
        tabbedPane.addTab("Current Response", currentScroll)


        self._storedArea = JTextArea()
        self._storedArea.setEditable(False)
        self._storedArea.setFont(Font("Courier New", Font.PLAIN, 9))
        self._storedArea.setBackground(Color(30, 30, 30))
        self._storedArea.setForeground(Color(200, 200, 200))
        storedScroll = JScrollPane(self._storedArea)
        tabbedPane.addTab("Stored Response", storedScroll)

        
        self._diffArea = JTextArea()
        self._diffArea.setEditable(False)
        self._diffArea.setFont(Font("Courier New", Font.PLAIN, 9))
        self._diffArea.setBackground(Color(30, 30, 30))
        self._diffArea.setForeground(Color(76, 175, 80))
        diffScroll = JScrollPane(self._diffArea)
        tabbedPane.addTab("Diff Analysis", diffScroll)

        
        self._issuesTable = JTable(DefaultTableModel(["Issue Type", "Severity", "Description", "Location"], 0))
        self._issuesTable.setBackground(Color(30, 30, 30))
        self._issuesTable.setForeground(Color(200, 200, 200))
        self._issuesTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        issuesScroll = JScrollPane(self._issuesTable)
        tabbedPane.addTab("Security Issues", issuesScroll)

        
        buttonPanel = JPanel()
        self._storeButton = JButton("Store Current Response")
        self._storeButton.addActionListener(self.onStore)
        self._compareButton = JButton("Compare & Analyze")
        self._compareButton.addActionListener(self.onCompare)
        self._clearButton = JButton("Clear Stored")
        self._clearButton.addActionListener(self.onClear)
        buttonPanel.add(self._storeButton)
        buttonPanel.add(self._compareButton)
        buttonPanel.add(self._clearButton)

        panel.add(tabbedPane, BorderLayout.CENTER)
        panel.add(buttonPanel, BorderLayout.SOUTH)

        return panel

    def getTabCaption(self):
        return "API Security Suite"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        if not isRequest:
            try:
                response_info = self._helpers.analyzeResponse(content)
                headers = response_info.getHeaders()
                content_type = self._getHeader(headers, "Content-Type")
                return content_type and ("json" in content_type.lower() or "graphql" in content_type.lower())
            except:
                return False
        return False

    def setMessage(self, content, isRequest):
        if content is None:
            self._rawResponseArea.setText("")
            self._currentArea.setText("")
        else:
            if not isRequest:
                self._currentMessage = content
                response_info = self._helpers.analyzeResponse(content)
                body = content[response_info.getBodyOffset():].tostring()
                self._rawResponseArea.setText(body)
                self._currentArea.setText(body)

    def onAnalyze(self, event):
        if self._currentMessage is None:
            self._analysisArea.setText("[!] No response loaded")
            return

        response_info = self._helpers.analyzeResponse(self._currentMessage)
        body = self._currentMessage[response_info.getBodyOffset():].tostring()

        try:
            analysis_report = self.analyzeResponse(body)
            self._analysisArea.setText(analysis_report["report"])
            self._populateFieldsTable(analysis_report["fields"])
        except Exception as e:
            self._analysisArea.setText("[!] Error during analysis:\n" + str(e))

    def analyzeResponse(self, body):
        report = []
        fields = []
        
        report.append("[*] API Response Analyzer Report")
        report.append("=" * 60)
        report.append("")

        try:
            data = json.loads(body)
            report.append("[+] Content-Type: JSON")
            report.append("")

            report.append("[*] Data Exposure Analysis:")
            report.append("-" * 60)
            
            exposed_patterns = self._detectExposurePatterns(data)
            if exposed_patterns:
                for pattern in exposed_patterns:
                    report.append("  [RISK] " + pattern)
                    fields.append({
                        "name": pattern.split("->")[0].strip() if "->" in pattern else pattern,
                        "value": "Found",
                        "risk": "HIGH"
                    })
            else:
                report.append("  [OK] No obvious data exposure detected")

            report.append("")
            report.append("[*] Sensitive Fields Detected:")
            report.append("-" * 60)
            sensitive_fields = self._extractSensitiveFields(data)
            if sensitive_fields:
                for field, value in sensitive_fields:
                    report.append("  [!] {}: {}...".format(field, str(value)[:50]))
                    fields.append({
                        "name": field,
                        "value": str(value)[:100],
                        "risk": "MEDIUM"
                    })
            else:
                report.append("  [OK] No sensitive fields found")

            report.append("")
            report.append("[*] Response Structure:")
            report.append("-" * 60)
            structure = self._analyzeStructure(data)
            for line in structure:
                report.append("  " + line)

        except:
            report.append("[!] Failed to parse as JSON, trying RAW analysis...")
            report.append("")
            raw_fields = self._rawAnalysis(body)
            for field in raw_fields:
                report.append("  [FOUND] " + field)
                fields.append({
                    "name": field,
                    "value": "Found in response",
                    "risk": "MEDIUM"
                })

        report.append("")
        report.append("=" * 60)
        report.append("[*] Analysis complete")

        return {
            "report": "\n".join(report),
            "fields": fields
        }

    def _detectExposurePatterns(self, data):
        patterns = []
        suspicious_keys = [
            "userId", "user_id", "uid", "id",
            "internalId", "internal_id",
            "isAdmin", "is_admin", "is_moderator",
            "permission", "permissions",
            "authorization", "token",
            "email", "phone", "ssn", "creditCard"
        ]

        def scan(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = path + "." + k if path else k
                    if k.lower() in [x.lower() for x in suspicious_keys]:
                        patterns.append("{} -> {} (Type: {})".format(new_path, type(v).__name__, v if isinstance(v, (int, bool)) else "***"))
                    scan(v, new_path)
            elif isinstance(obj, list) and obj:
                scan(obj[0], path + "[0]")

        scan(data)
        return patterns

    def _extractSensitiveFields(self, data):
        fields = []
        patterns = ["email", "phone", "password", "token", "secret", "key", "ssn", "creditcard"]

        def scan(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if any(pattern in k.lower() for pattern in patterns):
                        fields.append((k, v))
                    scan(v)
            elif isinstance(obj, list):
                for item in obj:
                    scan(item)

        scan(data)
        return fields

    def _analyzeStructure(self, data):
        lines = []
        lines.append("Type: {}".format(type(data).__name__))
        if isinstance(data, dict):
            lines.append("Root Keys: {}".format(len(data)))
            for key in list(data.keys())[:10]:
                lines.append("  - {}: {}".format(key, type(data[key]).__name__))
        elif isinstance(data, list):
            lines.append("Array Length: {}".format(len(data)))
            if data:
                lines.append("Item Type: {}".format(type(data[0]).__name__))
        return lines

    def _rawAnalysis(self, body):
        fields = []
        patterns = {
            "userId/uid": r'["\']?(user_?id|uid)["\']?\s*[:=]\s*(\d+)',
            "email": r'["\']?(email|mail)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "token": r'["\']?(token|jwt|auth)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        }
        
        for pattern_name, regex in patterns.items():
            matches = re.findall(regex, body, re.IGNORECASE)
            if matches:
                fields.append("{}: {} matches found".format(pattern_name, len(matches)))
        
        return fields

    def _populateFieldsTable(self, fields):
        model = self._fieldsTable.getModel()
        model.setRowCount(0)
        for field in fields:
            model.addRow([field["name"], field["value"], field["risk"]])

    

    def onDetect(self, event):
        if self._currentMessage is None:
            self._introspectionArea.setText("[!] No response loaded")
            return

        response_info = self._helpers.analyzeResponse(self._currentMessage)
        body = self._currentMessage[response_info.getBodyOffset():].tostring()

        try:
            data = json.loads(body)
            hidden_fields = self._detectHiddenFields(data)
            self._populateHiddenFieldsTable(hidden_fields)
            self._analyzeGraphQL(body)
        except Exception as e:
            self._introspectionArea.setText("[!] Error: " + str(e))

    def _detectHiddenFields(self, data):
        found = []

        def scan(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = path + "." + key if path else key
                    for category, fields in self.HIDDEN_FIELDS.items():
                        if key in fields or key.lower() in [f.lower() for f in fields]:
                            found.append({
                                "name": key,
                                "path": new_path,
                                "value": str(value)[:50],
                                "category": category,
                                "risk": self._calculateRisk(key, category)
                            })
                    scan(value, new_path)
            elif isinstance(obj, list) and obj:
                scan(obj[0], path + "[0]")

        scan(data)
        return found

    def _calculateRisk(self, field_name, category):
        if category in ["admin_fields", "security_fields"]:
            return "CRITICAL"
        elif category in ["debug_fields", "system_fields"]:
            return "HIGH"
        else:
            return "MEDIUM"

    def _analyzeGraphQL(self, body):
        analysis = []
        analysis.append("[*] GraphQL Hidden Field Analysis")
        analysis.append("=" * 60)

        if "__typename" in body:
            analysis.append("[+] GraphQL __typename found - can enumerate types")

        if "__schema" in body or "__type" in body:
            analysis.append("[+] Introspection fields detected - full schema may be queryable")
            analysis.append("[!] Try: { __schema { types { name } } }")

        if "alias" in body.lower():
            analysis.append("[+] GraphQL aliases detected - can bypass rate limits")

        if "fragment" in body.lower() or "__typename" in body:
            analysis.append("[+] Fragments/unions used - can exploit field merging")

        analysis.append("")
        analysis.append("[*] Common GraphQL bypass techniques:")
        analysis.append("  1. Use aliases to bypass rate limits")
        analysis.append("  2. Query __typename to enumerate types")
        analysis.append("  3. Use fragments for field merging attacks")
        analysis.append("  4. Try batching queries for auth bypass")

        self._introspectionArea.setText("\n".join(analysis))

    def _populateHiddenFieldsTable(self, fields):
        model = self._hiddenTable.getModel()
        model.setRowCount(0)

        exploit_suggestions = {
            "admin_fields": "Try modifying this field to escalate privileges",
            "debug_fields": "Debug mode enabled - may leak sensitive info",
            "system_fields": "Internal system data exposed - useful for IDOR",
            "security_fields": "Token/key exposed - test for reuse/replay",
            "feature_flags": "Disabled features may be enabled by toggling",
            "graphql_introspection": "Query __schema to enumerate entire API"
        }

        for field in fields:
            exploit = exploit_suggestions.get(field["category"], "Investigate further")
            model.addRow([
                field["name"],
                field["category"],
                field["risk"],
                exploit
            ])

    def onGenerateExploits(self, event):
        if self._currentMessage is None:
            self._payloadArea.setText("[!] No response loaded")
            return

        response_info = self._helpers.analyzeResponse(self._currentMessage)
        body = self._currentMessage[response_info.getBodyOffset():].tostring()

        try:
            data = json.loads(body)
            payloads = self._generateExploitPayloads(data)
            self._payloadArea.setText("\n\n".join(payloads))
        except:
            self._payloadArea.setText("[!] Failed to generate payloads")

    def _generateExploitPayloads(self, data):
        payloads = []

        payloads.append("# GraphQL Introspection Query")
        payloads.append("query { __schema { types { name description fields { name } } } }")
        payloads.append("")

        payloads.append("# Privilege Escalation (if isAdmin field found)")
        payloads.append('{"query": "query { user { id isAdmin name email } }"}')
        payloads.append('# Try mutation: mutation { updateUser(id: 1, isAdmin: true) { id isAdmin } }')
        payloads.append("")

        payloads.append("# Rate limit bypass using aliases")
        payloads.append('{"query": "{ a1: user(id:1) { id } a2: user(id:2) { id } a3: user(id:3) { id } ... }"}')
        payloads.append("")

        payloads.append("# Type confusion via fragments")
        payloads.append("""query {
  user {
    ...on Admin { password secretKey }
    ...on User { email }
  }
}""")
        payloads.append("")

        payloads.append("# Batch queries (bypass auth checks)")
        payloads.append('[{"query": "query { me { id } }"}, {"query": "query { otherUser(id:2) { id email } }"}]')

        return payloads

    

    def onStore(self, event):
        if self._currentMessage is None:
            self._diffArea.setText("[!] No response to store")
            return

        response_info = self._helpers.analyzeResponse(self._currentMessage)
        body = self._currentMessage[response_info.getBodyOffset():].tostring()
        
        self._storedResponse = body
        self._storedRequestInfo = response_info
        self._storedArea.setText(body)
        self._diffArea.setText("[+] Response stored successfully. Make another request and click Compare.")

    def onCompare(self, event):
        if self._storedResponse is None:
            self._diffArea.setText("[!] No stored response. Store a response first.")
            return

        if self._currentMessage is None:
            self._diffArea.setText("[!] No current response to compare")
            return

        response_info = self._helpers.analyzeResponse(self._currentMessage)
        current_body = self._currentMessage[response_info.getBodyOffset():].tostring()

        try:
            stored_json = json.loads(self._storedResponse)
            current_json = json.loads(current_body)

            diff_report = self._analyzeDiff(stored_json, current_json)
            security_issues = self._detectSecurityIssues(diff_report)

            self._diffArea.setText(diff_report["text"])
            self._populateIssuesTable(security_issues)

        except Exception as e:
            self._diffArea.setText("[!] Error during comparison: " + str(e))

    def _analyzeDiff(self, stored, current):
        report = []
        report.append("[*] Response Difference Analysis")
        report.append("=" * 80)
        report.append("")

        stored_keys = self._extractAllKeys(stored)
        current_keys = self._extractAllKeys(current)

        added_keys = current_keys - stored_keys
        removed_keys = stored_keys - current_keys
        common_keys = stored_keys & current_keys

        if added_keys:
            report.append("[+] NEW FIELDS in current response:")
            for key in sorted(added_keys):
                report.append("    - {}".format(key))
        
        if removed_keys:
            report.append("[-] REMOVED FIELDS in current response:")
            for key in sorted(removed_keys):
                report.append("    - {}".format(key))

        if common_keys:
            report.append("[~] CHANGED VALUES in common fields:")
            changed = self._findValueChanges(stored, current, common_keys)
            for key, old_val, new_val in changed:
                report.append("    - {}: {} -> {}".format(key, str(old_val)[:30], str(new_val)[:30]))

        report.append("")
        report.append("[*] Data Exposure Analysis:")
        report.append("-" * 80)
        
        sensitive_exposed = self._findSensitiveExposure(stored, current)
        if sensitive_exposed:
            for item in sensitive_exposed:
                report.append("[!] {}: exposed when auth removed".format(item))
        else:
            report.append("[OK] No obvious sensitive data exposure detected")

        report.append("")
        report.append("[*] Authorization Issues:")
        report.append("-" * 80)

        auth_issues = self._detectAuthBypass(stored, current)
        if auth_issues:
            for issue in auth_issues:
                report.append("[RISK] {}".format(issue))
        else:
            report.append("[OK] No obvious authorization issues")

        return {
            "text": "\n".join(report),
            "added": added_keys,
            "removed": removed_keys,
            "changed": self._findValueChanges(stored, current, common_keys),
            "auth_issues": auth_issues
        }

    def _extractAllKeys(self, obj, prefix=""):
        keys = set()
        
        def scan(o, path=""):
            if isinstance(o, dict):
                for k, v in o.items():
                    full_key = path + "." + k if path else k
                    keys.add(full_key)
                    scan(v, full_key)
            elif isinstance(o, list) and o:
                scan(o[0], path + "[0]")
        
        scan(obj, prefix)
        return keys

    def _findValueChanges(self, stored, current, keys):
        changes = []
        
        def get_value(obj, path):
            parts = path.split(".")
            current_val = obj
            for part in parts:
                if isinstance(current_val, dict):
                    current_val = current_val.get(part)
                elif isinstance(current_val, list) and part == "[0]":
                    current_val = current_val[0] if current_val else None
                else:
                    return None
            return current_val

        for key in keys:
            stored_val = get_value(stored, key)
            current_val = get_value(current, key)
            if stored_val != current_val:
                changes.append((key, stored_val, current_val))

        return changes

    def _findSensitiveExposure(self, authenticated, unauthenticated):
        sensitive_patterns = ["email", "phone", "password", "token", "secret", "ssn", "credit"]
        exposed = []

        auth_keys = self._extractAllKeys(authenticated)
        unauth_keys = self._extractAllKeys(unauthenticated)

        for key in unauth_keys:
            if key not in auth_keys:
                if any(pattern in key.lower() for pattern in sensitive_patterns):
                    exposed.append(key)

        return exposed

    def _detectAuthBypass(self, authenticated, unauthenticated):
        issues = []

        auth_data = json.dumps(authenticated, sort_keys=True)
        unauth_data = json.dumps(unauthenticated, sort_keys=True)

        if auth_data == unauth_data:
            issues.append("Response identical with/without auth - Complete authorization bypass")
        
        if "user" in unauth_data.lower() and "id" in unauth_data.lower():
            issues.append("User data accessible without authentication")
        
        if any(admin in unauth_data for admin in ["isAdmin", "is_admin", "admin", "permission"]):
            issues.append("Admin/permission fields visible in unauthenticated response")

        return issues

    def _detectSecurityIssues(self, diff_report):
        issues = []

        if diff_report["added"]:
            for key in diff_report["added"]:
                if any(x in key.lower() for x in ["email", "phone", "ssn", "token"]):
                    issues.append({
                        "type": "Information Disclosure",
                        "severity": "HIGH",
                        "description": "Sensitive field exposed: {}".format(key),
                        "location": key
                    })

        for issue in diff_report["auth_issues"]:
            issues.append({
                "type": "Authorization Bypass",
                "severity": "CRITICAL",
                "description": issue,
                "location": "Response Body"
            })

        if diff_report["changed"]:
            for key, old, new in diff_report["changed"][:3]:
                if old and new and str(old) != str(new):
                    issues.append({
                        "type": "Data Inconsistency",
                        "severity": "MEDIUM",
                        "description": "Value changed in {} field".format(key),
                        "location": key
                    })

        return issues

    def _populateIssuesTable(self, issues):
        model = self._issuesTable.getModel()
        model.setRowCount(0)
        
        for issue in issues:
            model.addRow([
                issue["type"],
                issue["severity"],
                issue["description"],
                issue["location"]
            ])

    def onClear(self, event):
        self._storedResponse = None
        self._storedArea.setText("")
        self._diffArea.setText("[+] Stored response cleared")
        self._issuesTable.getModel().setRowCount(0)

    def _getHeader(self, headers, header_name):
        for header in headers:
            if header.split(":")[0].strip().lower() == header_name.lower():
                return header.split(":", 1)[1].strip()
        return None

    def getMessage(self):
        return self._currentMessage

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

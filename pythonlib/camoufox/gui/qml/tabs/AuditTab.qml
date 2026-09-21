import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

//: Audit tab: configuration on the left, the live run and its results on the
//: right. The run log has its own tab, so this page stays about running an audit
//: -- its live progress and findings -- rather than about reading a finished one.
Item {
    id: auditTab

    //: Result of the last "Export summary", shown until the next one.
    property string exportMessage: ""

    //: Holds the findings as text so "Copy findings" has something to select.
    //: Never shown; a TextEdit is the only thing that can reach the clipboard.
    TextEdit {
        id: findingsClip
        visible: false
        text: auditBackend.findings.join("\n")
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // ---- left: configuration ----
        Rectangle {
            Layout.preferredWidth: Math.round(330 * Theme.scale)
            Layout.fillHeight: true
            color: Theme.bg

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    height: Theme.row
                    color: Theme.fg
                    Rule { anchors.bottom: parent.bottom }
                    Header {
                        anchors.left: parent.left
                        anchors.leftMargin: Theme.s3
                        anchors.verticalCenter: parent.verticalCenter
                        text: "AUDIT TARGET"
                    }
                }

                Flickable {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    contentHeight: cfgCol.implicitHeight + Theme.s4
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds

                    ColumnLayout {
                        id: cfgCol
                        width: parent.width
                        spacing: Theme.s2
                        anchors.margins: Theme.s3

                        Item { Layout.preferredHeight: Theme.s1 }

                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Only audit a site you own or have written permission to test."
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "TARGET URL"
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            placeholder: "https://staging.example.com/"
                            Component.onCompleted: text = auditBackend.target
                            onTextChanged: auditBackend.setTarget(text)
                        }

                        // The authorized scope is derived from the target URL, not
                        // typed: there is no "Authorized hosts" field by design.
                        // It is shown instead, because a scope the operator cannot
                        // see is a scope they cannot check.
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            spacing: Theme.s2
                            Header { text: "AUDITED SCOPE" }
                            Item { Layout.fillWidth: true }
                            Tag {
                                text: auditBackend.derivedHost ? auditBackend.derivedHost : "derived from target"
                                accent: auditBackend.derivedHost ? Theme.accent : Theme.muted
                            }
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: auditBackend.scopeDescription
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "SUBDOMAINS"
                        }
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            spacing: Theme.s2
                            RadioButton {
                                id: includeSubs
                                text: "Include subdomains"
                                checked: auditBackend.includeSubdomains
                                onToggled: if (checked) auditBackend.setIncludeSubdomains(true)
                            }
                            RadioButton {
                                id: excludeSubs
                                text: "Exclude subdomains"
                                checked: auditBackend.subdomainsExcluded
                                onToggled: if (checked) auditBackend.setSubdomainsExcluded(true)
                            }
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            visible: auditBackend.includeSubdomains
                            text: "Visitors browse the main site and its subdomains. Each visitor's page count is drawn as a random 1..N, so the population is a mix of short and long sessions."
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            visible: auditBackend.subdomainsExcluded
                            text: "Static page: subdomains are out of scope and each visitor loads only the target, once. Max requests / visitor is pinned to 1."
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "OUTBOUND FUNNEL (PROMOTIONAL BANNERS)"
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Follow promotional banners the audited page actually serves, and record click-through and landing-page engagement. Only banners pointing at hosts below (or already in scope) are ever followed."
                        }
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            spacing: Theme.s2
                            CheckBox {
                                id: funnelBox
                                text: "Audit banner click-throughs"
                                checked: auditBackend.enableOutboundFunnel
                                onToggled: auditBackend.setEnableOutboundFunnel(checked)
                            }
                        }
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            spacing: Theme.s2
                            visible: auditBackend.enableOutboundFunnel
                            CheckBox {
                                id: iframeBox
                                text: "Inspect banners inside iframes"
                                checked: auditBackend.includeIframes
                                onToggled: auditBackend.setIncludeIframes(checked)
                            }
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            visible: auditBackend.enableOutboundFunnel && !auditBackend.includeIframes
                            text: "Main document only. Campaigns served from an ad iframe will not be discovered, and the funnel may report no banner on a page that is showing one."
                        }
                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "EXCLUDE CAMPAIGN HOSTS"
                            visible: auditBackend.enableOutboundFunnel
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            visible: auditBackend.enableOutboundFunnel
                            placeholder: "ads.example.net (optional)"
                            Component.onCompleted: text = auditBackend.excludeHosts
                            onTextChanged: auditBackend.setExcludeHosts(text)
                        }
                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "CAMPAIGN INTERACTION RATE (%)"
                            visible: auditBackend.enableOutboundFunnel
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            visible: auditBackend.enableOutboundFunnel
                            placeholder: "2.5"
                            Component.onCompleted: text = auditBackend.campaignRatePct
                            onTextChanged: auditBackend.setCampaignRatePct(text)
                        }

                        // No authorization checkbox and no ticket field: starting
                        // the audit is the acknowledgment. The note below states
                        // what the run will record, so the state is still visible
                        // rather than merely assumed.
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Starting the audit authorizes it and records the approval as \""
                                  + auditBackend.acknowledgmentNote
                                  + "\". Only audit a site you own or have written permission to test."
                        }

                        Rule {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "TRAFFIC PLAN"
                        }

                        GridLayout {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            columns: 2
                            columnSpacing: Theme.s2
                            rowSpacing: Theme.s1

                            Muted { text: "Visitors" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.visitors
                                enabled: !auditBackend.singleLevelMode
                                input.validator: IntValidator { bottom: 0; top: 1000000 }
                                onEditingFinished: if (text.length) auditBackend.setVisitors(parseInt(text))
                            }

                            Muted { text: "Over (hours)" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.hours
                                input.validator: DoubleValidator { bottom: 0.01; top: 8760 }
                                onEditingFinished: if (text.length) auditBackend.setHours(parseFloat(text))
                            }

                            Muted { text: "Arrival pattern" }
                            Combo {
                                Layout.fillWidth: true
                                model: auditBackend.patternOptions
                                currentIndex: auditBackend.patternIndex
                                onActivated: auditBackend.setPatternIndex(currentIndex)
                            }

                            Muted { text: "Max evasion level" }
                            Combo {
                                Layout.fillWidth: true
                                model: ["0 - Naive HTTP", "1 - Headless", "2 - Headers", "3 - Fingerprint", "4 - Proxy rotation", "5 - Behavior", "6 - Persistent"]
                                currentIndex: auditBackend.maxLevel
                                enabled: !auditBackend.singleLevelMode
                                onActivated: auditBackend.setMaxLevel(currentIndex)
                            }

                            Muted { text: "Single level" }
                            Combo {
                                Layout.fillWidth: true
                                model: ["0 - Naive HTTP", "1 - Headless", "2 - Headers", "3 - Fingerprint", "4 - Proxy rotation", "5 - Behavior", "6 - Persistent"]
                                currentIndex: auditBackend.singleLevel
                                enabled: auditBackend.singleLevelMode
                                onActivated: auditBackend.setSingleLevel(currentIndex)
                            }

                            Muted { text: "Seed (optional)" }
                            Input {
                                Layout.fillWidth: true
                                placeholder: "random"
                                Component.onCompleted: text = auditBackend.seed
                                onTextChanged: auditBackend.setSeed(text)
                            }

                            Muted { text: "Cooldown between levels (s)" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.cooldownSeconds
                                input.validator: DoubleValidator { bottom: 0; top: 86400 }
                                onEditingFinished: if (text.length) auditBackend.setCooldownSeconds(parseFloat(text))
                            }

                            Muted { text: "Max requests / visitor" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxRequestsPerVisitor
                                // Pinned to 1 when subdomains are excluded: a
                                // static page is one page per visitor, so an
                                // editable N there would promise journeys the
                                // scope cannot deliver. The backend clamps it too,
                                // since a disabled field is not an enforcement.
                                enabled: !auditBackend.maxRequestsPerVisitorLocked
                                opacity: enabled ? 1.0 : 0.5
                                input.validator: IntValidator { bottom: 1; top: 10000 }
                                onEditingFinished: if (text.length) auditBackend.setMaxRequestsPerVisitor(parseInt(text))
                            }
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: auditBackend.maxRequestsPerVisitorHint
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "EXTRA PATHS"
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "One in-scope path per line, sampled alongside the target URL, e.g. /pricing. The root is always visited."
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            placeholder: "/pricing"
                            Component.onCompleted: text = auditBackend.extraPaths
                            onTextChanged: auditBackend.setExtraPaths(text)
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "CUSTOM HEADERS"
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "One 'Name: value' per line, sent on every request. Use this to audit a surface behind a login with a session cookie or token you already hold. A malformed line stops the run rather than being dropped."
                        }
                        TextArea {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            placeholder: "Cookie: session=...\nAuthorization: Bearer ..."
                            Component.onCompleted: text = auditBackend.extraHeaders
                            onTextChanged: auditBackend.setExtraHeaders(text)
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "EVIDENCE ARTIFACTS"
                        }
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            spacing: Theme.s1
                            Input {
                                id: artifactInput
                                Layout.fillWidth: true
                                placeholder: "(off) screenshots + HTML per level"
                                Component.onCompleted: text = auditBackend.artifactDir
                                onTextChanged: auditBackend.setArtifactDir(text)
                            }
                            Btn {
                                text: "Browse"
                                onClicked: {
                                    var r = auditBackend.browseArtifactDir()
                                    if (r.path) artifactInput.text = r.path
                                }
                            }
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "When set, the first visit of each level writes a screenshot and the served HTML. A block or challenge page is captured too, which is the page worth keeping."
                        }

                        // Schedule preview
                        Rectangle {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            implicitHeight: prevCol.implicitHeight + Theme.s3
                            color: Theme.fg
                            radius: Theme.s1
                            border.color: Theme.border
                            border.width: 1

                            ColumnLayout {
                                id: prevCol
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.margins: Theme.s2
                                spacing: Theme.s1

                                Header { text: "ARRIVAL PREVIEW" }

                                Row {
                                    spacing: 2
                                    Repeater {
                                        model: auditBackend.schedulePreview
                                        Rectangle {
                                            width: Math.max(2, Math.round((prevCol.width - Theme.s4) / 24) - 2)
                                            height: Math.max(3, Math.round(28 * (modelData / Math.max(1, auditBackend.maxPreview()))))
                                            anchors.bottom: parent.bottom
                                            color: Theme.accent
                                            opacity: 0.35 + 0.65 * (modelData / Math.max(1, auditBackend.maxPreview()))
                                        }
                                    }
                                }

                                Muted {
                                    Layout.fillWidth: true
                                    wrapMode: Text.WordWrap
                                    text: auditBackend.schedulePreviewSummary
                                }
                            }
                        }

                        Rule {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "PROXY"
                        }

                        GridLayout {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            columns: 2
                            columnSpacing: Theme.s2
                            rowSpacing: Theme.s1

                            Muted { text: "Mode" }
                            Combo {
                                Layout.fillWidth: true
                                model: auditBackend.proxyModeOptions
                                currentIndex: auditBackend.proxyModeIndex
                                onActivated: auditBackend.setProxyModeIndex(currentIndex)
                            }

                            Muted {
                                visible: auditBackend.proxyModeIndex === 1
                                text: "List file"
                            }
                            RowLayout {
                                visible: auditBackend.proxyModeIndex === 1
                                Layout.fillWidth: true
                                spacing: Theme.s1
                                Input {
                                    id: proxyFileInput
                                    Layout.fillWidth: true
                                    placeholder: "/path/to/proxies.txt"
                                    Component.onCompleted: text = auditBackend.proxyFile
                                    onTextChanged: auditBackend.setProxyFile(text)
                                }
                                Btn {
                                    text: "Browse"
                                    onClicked: {
                                        var r = auditBackend.browseProxyFile()
                                        if (r.path) proxyFileInput.text = r.path
                                        proxyStatus.text = r.message
                                        proxyStatus.color = r.ok ? Theme.ok : Theme.err
                                    }
                                }
                                Btn {
                                    text: "Check"
                                    onClicked: {
                                        var r = auditBackend.validateProxyFile(proxyFileInput.text)
                                        proxyStatus.text = r.message
                                        proxyStatus.color = r.ok ? Theme.ok : Theme.err
                                    }
                                }
                            }

                            Muted {
                                visible: auditBackend.proxyModeIndex === 2
                                text: "Gateway"
                            }
                            Input {
                                visible: auditBackend.proxyModeIndex === 2
                                Layout.fillWidth: true
                                placeholder: "http://user-session-{session}:pass@host:8000"
                                Component.onCompleted: text = auditBackend.proxyGateway
                                onTextChanged: auditBackend.setProxyGateway(text)
                            }

                            Muted {
                                visible: auditBackend.proxyModeIndex === 1
                                text: "Policy"
                            }
                            Combo {
                                visible: auditBackend.proxyModeIndex === 1
                                Layout.fillWidth: true
                                model: auditBackend.proxyPolicyOptions
                                currentIndex: auditBackend.proxyPolicyIndex
                                onActivated: auditBackend.setProxyPolicyIndex(currentIndex)
                            }

                            Muted { text: "Per-proxy cap" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxPerProxy
                                input.validator: IntValidator { bottom: 0; top: 100000 }
                                onEditingFinished: if (text.length) auditBackend.setMaxPerProxy(parseInt(text))
                            }
                        }

                        Muted {
                            id: proxyStatus
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: ""
                        }

                        Rule {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                        }

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "SAFETY CEILINGS"
                        }
                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "The audit stops when a ceiling is reached, rather than continuing."
                        }

                        GridLayout {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            columns: 2
                            columnSpacing: Theme.s2
                            rowSpacing: Theme.s1

                            // The global request ceiling is derived from the traffic
                            // plan, not typed: the numbers it needs are already
                            // above, so a second field could only disagree with
                            // them. Shown rather than editable, with its terms, so
                            // a run stopping here does not read as a bug.
                            Muted { text: "Max requests (derived)" }
                            Muted {
                                id: ceilingValue
                                Layout.fillWidth: true
                                color: Theme.fg
                                text: auditBackend.safetyCeilingSummary ? auditBackend.safetyCeilingSummary : "set a target and visitors to derive"
                            }

                            Muted { text: "Max requests/sec" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxRps
                                input.validator: DoubleValidator { bottom: 0; top: 100000 }
                                onEditingFinished: if (text.length) auditBackend.setMaxRps(parseFloat(text))
                            }

                            Muted { text: "Max concurrent" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxConcurrency
                                input.validator: IntValidator { bottom: 1; top: 512 }
                                onEditingFinished: if (text.length) auditBackend.setMaxConcurrency(parseInt(text))
                            }

                            Muted { text: "Max arrivals/min" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxPerMinute
                                input.validator: IntValidator { bottom: 1; top: 100000 }
                                onEditingFinished: if (text.length) auditBackend.setMaxPerMinute(parseInt(text))
                            }

                            Muted { text: "Report directory" }
                            Input {
                                Layout.fillWidth: true
                                placeholder: "optional"
                                Component.onCompleted: text = auditBackend.outDir
                                onTextChanged: auditBackend.setOutDir(text)
                            }

                            Muted { text: "Abort after N errors" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.abortAfterErrors
                                input.validator: IntValidator { bottom: 0; top: 100000 }
                                onEditingFinished: if (text.length) auditBackend.setAbortAfterErrors(parseInt(text))
                            }
                        }

                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "A rung aborts after this many consecutive transport "
                                  + "errors. 0 disables the ceiling. Keep it above a "
                                  + "handful: a handful of timeouts is normal, and an "
                                  + "abort turns a partial rung into no verdict at all."
                        }

                        CheckBox {
                            Layout.leftMargin: Theme.s3
                            text: "Reuse one browser per level"
                            checked: auditBackend.reuseBrowser
                            onToggled: auditBackend.setReuseBrowser(checked)
                        }

                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "On (default): one browser serves a whole rung and "
                                  + "each visitor opens its own context, which carries "
                                  + "its own fingerprint. Off: a fresh browser launches "
                                  + "per visit, so 100 visitors become 100 browser "
                                  + "processes - far slower, and a resource shape no "
                                  + "human population produces."
                        }

                        CheckBox {
                            Layout.leftMargin: Theme.s3
                            text: "Single-level mode (run one rung, skip L0 up to it)"
                            checked: auditBackend.singleLevelMode
                            onToggled: auditBackend.setSingleLevelMode(checked)
                        }

                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Off (default): the ladder runs from L0 up to the max "
                                  + "level, which is what attributes a verdict to the control "
                                  + "that holds. On: only the selected rung runs, with the "
                                  + "visitor count pinned to 100 so repeat runs at that rung "
                                  + "are comparable. A single rung cannot attribute a defense - "
                                  + "the report says so."
                        }

                        CheckBox {
                            Layout.leftMargin: Theme.s3
                            text: "Force headless for every level"
                            checked: auditBackend.headless
                            onToggled: auditBackend.setHeadless(checked)
                        }

                        Muted {
                            Layout.leftMargin: Theme.s3
                            Layout.fillWidth: true
                            wrapMode: Text.WordWrap
                            text: "Off (default): each level runs the posture it "
                                  + "defines - L1 headless, L2 and up headful - so the "
                                  + "ladder isolates one control at a time. On: every "
                                  + "browser level is forced headless, which is useful on "
                                  + "a host that cannot show a window but merges L1 into "
                                  + "the levels above it. The run says so when it overrides."
                        }

                        Item { Layout.preferredHeight: Theme.s2 }
                    }
                }
            }
        }

        // ---- right: run + results ----
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bg

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                // Run bar
                Rectangle {
                    Layout.fillWidth: true
                    height: Theme.row
                    color: Theme.fg
                    Rule { anchors.bottom: parent.bottom }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.s3
                        anchors.rightMargin: Theme.s3
                        spacing: Theme.s2

                        Btn {
                            text: "Start audit"
                            icon: "\uE768"
                            accent: auditBackend.canRun ? Theme.accent : Theme.muted
                            on: auditBackend.canRun
                            onClicked: auditBackend.start()
                        }

                        Btn {
                            text: "Stop"
                            accent: Theme.err
                            on: auditBackend.running
                            onClicked: auditBackend.stop()
                        }

                        Btn {
                            text: "Clear"
                            on: !auditBackend.running
                            onClicked: auditBackend.clearResults()
                        }

                        Item { Layout.fillWidth: true }

                        T {
                            visible: auditBackend.running
                            text: "running..."
                            color: Theme.accent
                        }

                        T {
                            visible: auditBackend.error.length > 0
                            text: auditBackend.error
                            color: Theme.err
                            Layout.maximumWidth: Math.round(320 * Theme.scale)
                            elide: Text.ElideRight
                        }
                    }
                }

                // Summary strip
                Rectangle {
                    Layout.fillWidth: true
                    visible: !!auditBackend.summary
                             && auditBackend.summary.visits !== undefined
                    implicitHeight: sumRow.implicitHeight + Theme.s2
                    color: Theme.fg

                    RowLayout {
                        id: sumRow
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: Theme.s3
                        spacing: Theme.s4

                        T {
                            text: "Visits: " + (auditBackend.summary.visits || 0)
                        }
                        T {
                            text: "Requests: " + (auditBackend.summary.requests || 0)
                        }
                        T {
                            text: "Duration: " + (auditBackend.summary.duration || 0) + "s"
                        }
                        T {
                            visible: auditBackend.summary.aborted === true
                            text: "ABORTED"
                            color: Theme.err
                        }
                        Item { Layout.fillWidth: true }
                    }
                }

                // Findings
                Rectangle {
                    Layout.fillWidth: true
                    visible: auditBackend.findings.length > 0
                    implicitHeight: Math.min(
                        Math.round(150 * Theme.scale),
                        findCol.implicitHeight + Theme.s3)
                    color: Theme.bg

                    ColumnLayout {
                        id: findCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: Theme.s3
                        spacing: Theme.s1

                        Header { text: "FINDINGS" }

                        Repeater {
                            model: auditBackend.findings
                            Muted {
                                Layout.fillWidth: true
                                wrapMode: Text.WordWrap
                                text: "* " + modelData
                            }
                        }
                    }
                }

                // Level summary
                Rectangle {
                    Layout.fillWidth: true
                    visible: !!auditBackend.summary
                             && !!auditBackend.summary.levels
                             && auditBackend.summary.levels.length > 0
                    implicitHeight: lvlRow.implicitHeight + Theme.s3
                    color: Theme.fg

                    Row {
                        id: lvlRow
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Theme.s3
                        spacing: Theme.s4

                        Repeater {
                            model: auditBackend.summary.levels || []
                            Column {
                                spacing: 2
                                T { text: modelData.name }
                                Muted {
                                    text: "bypass " + Math.round(modelData.bypassRate * 100) + "%  detected "
                                          + Math.round(modelData.detectionRate * 100) + "%"
                                }
                                Muted {
                                    visible: !!modelData.vendors
                                    text: modelData.vendors
                                    color: Theme.accent
                                }
                            }
                        }
                    }
                }

                // Outbound funnel card. Shown only when the run
                // measured click-throughs, so an ordinary audit
                // does not grow an empty panel.
                Rectangle {
                    id: funnelCard
                    Layout.fillWidth: true
                    Layout.preferredHeight: funnelCol.implicitHeight + Theme.s3 * 2
                    //: The funnel key is absent from a run that did
                    //: not measure click-throughs, and reading
                    //: through it warns on every summary refresh.
                    //: Resolve it once, here.
                    readonly property var f: auditBackend.summary
                                             && auditBackend.summary.funnel
                                             ? auditBackend.summary.funnel : ({})
                    visible: f.enabled === true
                    color: Theme.bg
                    border.color: Theme.muted
                    border.width: 1
                    radius: Theme.s1

                    ColumnLayout {
                        id: funnelCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: Theme.s3
                        spacing: Theme.s1

                        T {
                            text: "Outbound funnel"
                            color: Theme.accent
                        }
                        Muted {
                            text: "Interaction rate " + (funnelCard.f.ratePct || 0)
                                  + "%  clicks " + (funnelCard.f.clicks || 0)
                                  + "  landed " + (funnelCard.f.landed || 0)
                                  + "  engaged " + (funnelCard.f.engaged || 0)
                        }
                        Muted {
                            text: "First-party " + (funnelCard.f.firstPartyClicks || 0)
                                  + "  partner " + (funnelCard.f.partnerClicks || 0)
                                  + "  refused " + (funnelCard.f.refused || 0)
                                  + "  unreachable " + (funnelCard.f.unreachable || 0)
                        }
                        Muted {
                            visible: funnelCard.f.dwellP50 !== undefined
                                     && funnelCard.f.dwellP50 !== null
                            text: "Dwell p50 " + (funnelCard.f.dwellP50 || 0) + "s "
                                  + "(min " + (funnelCard.f.dwellMin || 0) + "s, "
                                  + "max " + (funnelCard.f.dwellMax || 0) + "s)"
                        }
                        Repeater {
                            model: funnelCard.f.destinations || []
                            delegate: Muted {
                                required property var modelData
                                text: "→ " + modelData.url + "  (" + modelData.clicks + " click"
                                      + (modelData.clicks === 1 ? "" : "s") + ")"
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }
                    }
                }

                // Visits table
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: Theme.bg
                    clip: true

                    ListView {
                        id: visitList
                        anchors.fill: parent
                        anchors.margins: Theme.s2
                        clip: true
                        model: auditBackend.visits
                        boundsBehavior: Flickable.StopAtBounds
                        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                        delegate: Rectangle {
                            // Declaring required properties opts out of the
                            // implicit `index`/`model` context properties, so
                            // `index` has to be requested explicitly.
                            required property int index
                            required property int visitorIndex
                            required property string levelName
                            required property string verdict
                            required property var httpStatus
                            required property string reason
                            required property color verdictColor
                            required property string source
                            required property string proxyLabel

                            width: visitList.width
                            height: Theme.row
                            color: index % 2 ? Theme.fg : "transparent"

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.s2
                                anchors.rightMargin: Theme.s2
                                spacing: Theme.s2

                                T {
                                    text: "#" + visitorIndex
                                    Layout.preferredWidth: Math.round(50 * Theme.scale)
                                    color: Theme.muted
                                }
                                T {
                                    text: levelName
                                    Layout.preferredWidth: Math.round(150 * Theme.scale)
                                    elide: Text.ElideRight
                                }
                                T {
                                    text: verdict
                                    color: verdictColor
                                    Layout.preferredWidth: Math.round(90 * Theme.scale)
                                }
                                T {
                                    text: httpStatus
                                    Layout.preferredWidth: Math.round(40 * Theme.scale)
                                    color: Theme.muted
                                }
                                T {
                                    text: source
                                    Layout.preferredWidth: Math.round(60 * Theme.scale)
                                    color: Theme.dim
                                }
                                Muted {
                                    Layout.fillWidth: true
                                    text: reason
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }

                    // The run log has its own tab: a full-height console reads far
                    // better than the strip that used to sit here. This footer is
                    // the signpost, so it does not become a page nobody finds.
                    Rectangle {
                        Layout.fillWidth: true
                        height: Theme.row
                        color: Theme.fg
                        Rule { anchors.top: parent.top }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.s3
                            anchors.rightMargin: Theme.s3
                            spacing: Theme.s2

                            Muted {
                                Layout.fillWidth: true
                                elide: Text.ElideRight
                                text: auditBackend.log.length
                                      ? auditBackend.log.length + " log line(s); run output is in its own tab."
                                      : "Run output has its own tab."
                            }
                            Btn {
                                text: "Copy findings"
                                on: auditBackend.findings.length > 0
                                onClicked: {
                                    findingsClip.selectAll()
                                    findingsClip.copy()
                                }
                            }
                            Btn {
                                text: "Export summary"
                                icon: "\uE74E"
                                on: auditBackend.summary.visits !== undefined
                                onClicked: {
                                    const r = auditBackend.browseExportText()
                                    auditTab.exportMessage = r.message || ""
                                }
                            }
                            Btn {
                                text: "Logs"
                                icon: "\uE756"
                                accent: Theme.accent
                                onClicked: root.openTab(4)
                            }
                        }
                    }
            }
        }
    }
}

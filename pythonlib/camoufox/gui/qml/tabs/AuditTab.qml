import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

//: Audit tab: configuration on the left, the live run and its results on the
//: right. The run log and the finished report each have their own tab, so this
//: page stays about running an audit -- its live progress and findings -- rather
//: than about reading a finished one.
Item {
    id: auditTab

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

                        Header {
                            Layout.leftMargin: Theme.s3
                            text: "AUTHORIZED HOSTS"
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            placeholder: "example.com"
                            Component.onCompleted: text = auditBackend.scopeHosts
                            onTextChanged: auditBackend.setScopeHosts(text)
                        }
                        RowLayout {
                            Layout.leftMargin: Theme.s3
                            spacing: Theme.s2
                            CheckBox {
                                id: subdomainsBox
                                text: "Include subdomains"
                                checked: auditBackend.allowSubdomains
                                onToggled: auditBackend.setAllowSubdomains(checked)
                            }
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
                            text: "PARTNER CAMPAIGN HOSTS"
                            visible: auditBackend.enableOutboundFunnel
                        }
                        Input {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            visible: auditBackend.enableOutboundFunnel
                            placeholder: "partner.example.net (optional)"
                            Component.onCompleted: text = auditBackend.outboundHosts
                            onTextChanged: auditBackend.setOutboundHosts(text)
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

                        // Authorization gate
                        Rectangle {
                            Layout.leftMargin: Theme.s3
                            Layout.rightMargin: Theme.s3
                            Layout.fillWidth: true
                            implicitHeight: ackCol.implicitHeight + Theme.s3 * 2
                            color: auditBackend.acknowledged ? "#1e2a1e" : "#2a1e1e"
                            radius: Theme.s1
                            border.color: auditBackend.acknowledged ? Theme.ok : Theme.err
                            border.width: 1

                            ColumnLayout {
                                id: ackCol
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.margins: Theme.s2
                                spacing: Theme.s1

                                CheckBox {
                                    id: ackBox
                                    text: "I am authorized to test this target"
                                    checked: auditBackend.acknowledged
                                    onToggled: auditBackend.setAcknowledged(checked)
                                }
                                Input {
                                    Layout.fillWidth: true
                                    placeholder: "Ticket / approval reference"
                                    Component.onCompleted: text = auditBackend.acknowledgmentNote
                                    onTextChanged: auditBackend.setAcknowledgmentNote(text)
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

                            Muted { text: "Max requests" }
                            Input {
                                Layout.fillWidth: true
                                text: auditBackend.maxRequests
                                input.validator: IntValidator { bottom: 0; top: 100000000 }
                                onEditingFinished: if (text.length) auditBackend.setMaxRequests(parseInt(text))
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

                    // The run log and the finished report each have their own tab: a
                    // full-height console and a full-width document both read far better
                    // than the strips that used to sit here. This footer is the signpost,
                    // so neither becomes a page nobody finds.
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
                                      ? auditBackend.log.length + " log line(s); output and the report are in their own tabs."
                                      : "Run output and the finished report each have their own tab."
                            }
                            Btn {
                                text: "Logs"
                                icon: "\uE756"
                                onClicked: root.openTab(4)
                            }
                            Btn {
                                text: "Reports"
                                icon: "\uE8A5"
                                accent: Theme.accent
                                on: auditBackend.summary.visits !== undefined
                                onClicked: root.openTab(5)
                            }
                        }
                    }
            }
        }
    }
}

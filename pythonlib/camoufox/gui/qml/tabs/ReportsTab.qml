import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

//: Reports tab.
//:
//: The Audit tab answers "what is happening"; this one answers "what happened".
//: Findings, the per-level bypass/detection table, the outbound funnel and the
//: report files the engine wrote are laid out as a document, so a finished run
//: can be read and handed on without scrolling a results pane four stations up.
//:
//: Every figure here comes from auditBackend.summary, which the backend builds
//: from the same payload the JSON/CSV/HTML reports are rendered from. Nothing
//: is recomputed in QML, so the page and the files cannot disagree.
Item {
    id: reportTab

    //: `auditBackend.summary` is an empty map before the first run, and reading
    //: through it warns on every refresh. Resolve both it and its list members
    //: once, here.
    readonly property var s: auditBackend.summary || ({})
    readonly property var levels: s.levels || []
    readonly property var funnel: s.funnel || ({})
    readonly property bool hasRun: s.visits !== undefined

    //: {fmt: path} -> a list, so the report files can be repeated over in a
    //: stable order rather than whatever key order the map happens to have.
    readonly property var writtenFiles: {
        const w = s.written || {}
        return ["html", "json", "csv"]
            .filter(f => w[f])
            .map(f => ({ fmt: f, path: w[f] }))
            .concat(Object.keys(w)
                .filter(f => ["html", "json", "csv"].indexOf(f) === -1)
                .map(f => ({ fmt: f, path: w[f] })))
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

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

                Header { text: "REPORT" }

                T {
                    visible: reportTab.hasRun
                    text: reportTab.s.visits + " visits"
                          + " / " + (reportTab.s.requests || 0) + " requests"
                          + " / " + (reportTab.s.duration || 0) + "s"
                    color: Theme.muted
                }

                T {
                    visible: reportTab.s.aborted === true
                    text: "ABORTED"
                    color: Theme.err
                }

                Item { Layout.fillWidth: true }

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
                    accent: Theme.accent
                    on: reportTab.hasRun
                    onClicked: {
                        const r = auditBackend.browseExportText()
                        reportTab.exportMessage = r.message || ""
                    }
                }

                Btn {
                    text: "Clear"
                    accent: Theme.err
                    on: reportTab.hasRun
                    onClicked: auditBackend.clearResults()
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bg

            Flickable {
                id: doc
                anchors.fill: parent
                anchors.margins: Theme.s3
                clip: true
                contentWidth: width
                contentHeight: docCol.implicitHeight
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                    id: docCol
                    width: doc.width
                    spacing: Theme.s3

                    // -- empty state ------------------------------------------
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.s4 * 3
                        spacing: Theme.s2
                        visible: !reportTab.hasRun

                        T {
                            Layout.alignment: Qt.AlignHCenter
                            text: "No report yet"
                            color: Theme.muted
                            font.pixelSize: Theme.textLg
                        }
                        Muted {
                            Layout.alignment: Qt.AlignHCenter
                            text: "Run an audit and its findings, per-level rates and report"
                                  + " files appear here."
                        }
                        Btn {
                            Layout.alignment: Qt.AlignHCenter
                            text: "Go to Audit"
                            accent: Theme.accent
                            onClicked: root.openTab(3)
                        }
                    }

                    // -- abort reason -----------------------------------------
                    Rectangle {
                        Layout.fillWidth: true
                        visible: reportTab.s.aborted === true
                        implicitHeight: abortCol.implicitHeight + Theme.s3 * 2
                        color: Theme.bg
                        border.color: Theme.err
                        border.width: 1
                        radius: Theme.s1

                        ColumnLayout {
                            id: abortCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: Theme.s3
                            spacing: Theme.s1

                            Bold { text: "Run aborted"; color: Theme.err }
                            Muted {
                                Layout.fillWidth: true
                                wrapMode: Text.WordWrap
                                text: reportTab.s.abortReason || "No reason recorded."
                            }
                        }
                    }

                    // -- report files -----------------------------------------
                    Rectangle {
                        Layout.fillWidth: true
                        visible: reportTab.writtenFiles.length > 0
                        implicitHeight: filesCol.implicitHeight + Theme.s3 * 2
                        color: Theme.fg
                        radius: Theme.s1

                        ColumnLayout {
                            id: filesCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: Theme.s3
                            spacing: Theme.s2

                            Header { text: "REPORT FILES" }

                            Repeater {
                                model: reportTab.writtenFiles

                                RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    spacing: Theme.s2

                                    Tag {
                                        text: modelData.fmt
                                        accent: Theme.accent
                                    }

                                    T {
                                        Layout.fillWidth: true
                                        text: modelData.path
                                        color: Theme.muted
                                        elide: Text.ElideMiddle
                                    }

                                    Btn {
                                        text: "Open"
                                        accent: Theme.accent
                                        onClicked: auditBackend.openPath(modelData.path)
                                    }
                                }
                            }
                        }
                    }

                    // -- levels -----------------------------------------------
                    Rectangle {
                        Layout.fillWidth: true
                        visible: reportTab.levels.length > 0
                        implicitHeight: lvlCol.implicitHeight + Theme.s3 * 2
                        color: Theme.bg
                        border.color: Theme.border
                        border.width: 1
                        radius: Theme.s1

                        ColumnLayout {
                            id: lvlCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.margins: Theme.s3
                            spacing: Theme.s1

                            Header { text: "PER-LEVEL OUTCOME" }

                            //: Column headings, aligned to the same widths the
                            //: rows use, so the table reads as a table.
                            RowLayout {
                                Layout.fillWidth: true
                                Layout.topMargin: Theme.s1
                                spacing: Theme.s2

                                Muted {
                                    text: "LEVEL"
                                    Layout.preferredWidth: Math.round(120 * Theme.scale)
                                }
                                Muted {
                                    text: "RUNS"
                                    Layout.preferredWidth: Math.round(60 * Theme.scale)
                                }
                                Muted {
                                    text: "BYPASS"
                                    Layout.preferredWidth: Math.round(60 * Theme.scale)
                                }
                                Muted {
                                    text: "DETECTED"
                                    Layout.preferredWidth: Math.round(70 * Theme.scale)
                                }
                                Muted { text: "VENDORS"; Layout.fillWidth: true }
                            }

                            Rule {}

                            Repeater {
                                model: reportTab.levels

                                RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    spacing: Theme.s2

                                    T {
                                        text: modelData.name
                                        Layout.preferredWidth: Math.round(120 * Theme.scale)
                                        elide: Text.ElideRight
                                        color: modelData.aborted ? Theme.err : Theme.text
                                    }
                                    T {
                                        text: modelData.completed
                                        Layout.preferredWidth: Math.round(60 * Theme.scale)
                                        color: Theme.muted
                                    }
                                    T {
                                        text: Math.round(modelData.bypassRate * 100) + "%"
                                        Layout.preferredWidth: Math.round(60 * Theme.scale)
                                        color: modelData.bypassRate > 0 ? Theme.ok : Theme.muted
                                    }
                                    T {
                                        text: Math.round(modelData.detectionRate * 100) + "%"
                                        Layout.preferredWidth: Math.round(70 * Theme.scale)
                                        color: modelData.detectionRate > 0 ? Theme.err : Theme.muted
                                    }
                                    Muted {
                                        Layout.fillWidth: true
                                        text: modelData.vendors || "-"
                                        elide: Text.ElideRight
                                    }
                                }
                            }
                        }
                    }

                    // -- outbound funnel --------------------------------------
                    Rectangle {
                        Layout.fillWidth: true
                        visible: reportTab.funnel.enabled === true
                        implicitHeight: funnelCol.implicitHeight + Theme.s3 * 2
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

                            Header { text: "OUTBOUND FUNNEL" }

                            Muted {
                                text: "Interaction rate " + (reportTab.funnel.ratePct || 0) + "%"
                                      + "   clicks " + (reportTab.funnel.clicks || 0)
                                      + "   landed " + (reportTab.funnel.landed || 0)
                                      + "   engaged " + (reportTab.funnel.engaged || 0)
                            }
                            Muted {
                                text: "First-party " + (reportTab.funnel.firstPartyClicks || 0)
                                      + "   partner " + (reportTab.funnel.partnerClicks || 0)
                                      + "   refused " + (reportTab.funnel.refused || 0)
                                      + "   unreachable " + (reportTab.funnel.unreachable || 0)
                            }
                            Muted {
                                visible: reportTab.funnel.dwellP50 !== undefined
                                         && reportTab.funnel.dwellP50 !== null
                                text: "Dwell p50 " + (reportTab.funnel.dwellP50 || 0) + "s"
                                      + "   min " + (reportTab.funnel.dwellMin || 0) + "s"
                                      + "   max " + (reportTab.funnel.dwellMax || 0) + "s"
                            }

                            Rule {
                                Layout.topMargin: Theme.s1
                                visible: (reportTab.funnel.destinations || []).length > 0
                            }

                            Repeater {
                                model: reportTab.funnel.destinations || []

                                RowLayout {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    spacing: Theme.s2

                                    Muted {
                                        Layout.fillWidth: true
                                        text: modelData.url
                                        elide: Text.ElideMiddle
                                    }
                                    T {
                                        text: modelData.clicks
                                              + (modelData.clicks === 1 ? " click" : " clicks")
                                        color: Theme.accent
                                    }
                                }
                            }
                        }
                    }

                    // -- findings ---------------------------------------------
                    Rectangle {
                        Layout.fillWidth: true
                        visible: auditBackend.findings.length > 0
                        implicitHeight: findCol.implicitHeight + Theme.s3 * 2
                        color: Theme.bg
                        border.color: Theme.border
                        border.width: 1
                        radius: Theme.s1

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

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.s2

                                    T {
                                        text: "\u2022"
                                        color: Theme.accent
                                        Layout.alignment: Qt.AlignTop
                                    }
                                    Muted {
                                        Layout.fillWidth: true
                                        wrapMode: Text.WordWrap
                                        text: modelData
                                    }
                                }
                            }
                        }
                    }

                    // -- export feedback --------------------------------------
                    Muted {
                        Layout.fillWidth: true
                        visible: reportTab.exportMessage.length > 0
                        text: reportTab.exportMessage
                        color: Theme.accent
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }
    }

    property string exportMessage: ""

    //: Holds the findings as text so "Copy findings" has something to select.
    //: Never shown; a TextEdit is the only thing that can reach the clipboard.
    TextEdit {
        id: findingsClip
        visible: false
        text: auditBackend.findings.join("\n")
    }
}
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../theme"
import "../components"

//: Logs tab.
//:
//: An audit writes a running commentary -- proxy validation, per-visitor
//: scheduling, scope refusals, report paths -- and until now it was squeezed
//: into a 96px strip under the results, so reading a failure meant scrolling a
//: box four lines tall.
//:
//: This gives it the whole page. Lines wrap rather than elide, because the
//: interesting half of a log line is usually its end.
Item {
    id: logTab

    //: Follow means "keep the newest line in view". It is a mode, not a state:
    //: scrolling back through a long run should not have the view yanked to the
    //: bottom by the next line, so moving away from the end turns it off.
    property bool follow: true

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

                Header { text: "RUN LOG" }

                T {
                    text: auditBackend.log.length
                          + (auditBackend.log.length === 1 ? " line" : " lines")
                    color: Theme.muted
                }

                Item { Layout.fillWidth: true }

                T {
                    visible: auditBackend.running
                    text: "running..."
                    color: Theme.accent
                }

                Btn {
                    text: logTab.follow ? "Following" : "Follow"
                    accent: logTab.follow ? Theme.accent : Theme.muted
                    on: auditBackend.log.length > 0
                    onClicked: {
                        logTab.follow = !logTab.follow
                        if (logTab.follow)
                            logFlick.contentY = logFlick.contentHeight - logFlick.height
                    }
                }

                Btn {
                    text: "Copy"
                    on: auditBackend.log.length > 0
                    onClicked: {
                        logText.selectAll()
                        logText.copy()
                    }
                }

                Btn {
                    text: "Clear"
                    accent: Theme.err
                    on: auditBackend.log.length > 0
                    onClicked: auditBackend.clearLog()
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.bg

            Flickable {
                id: logFlick
                anchors.fill: parent
                anchors.margins: Theme.s2
                clip: true
                contentWidth: width
                contentHeight: logText.contentHeight
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                //: Moving away from the end means the operator is reading
                //: something, so stop following. Programmatic scrolling does
                //: not emit movementEnded, so this only reacts to the user.
                onMovementEnded: if (!atYEnd) logTab.follow = false

                TextEdit {
                    id: logText
                    width: logFlick.width
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextEdit.Wrap
                    text: auditBackend.log.join("\n")
                    color: Theme.text
                    font.family: Theme.fontMain
                    font.pixelSize: Theme.textSm
                    selectedTextColor: Theme.bg
                    selectionColor: Theme.accent
                }
            }

            Muted {
                anchors.centerIn: parent
                visible: auditBackend.log.length === 0
                text: auditBackend.running
                      ? "Waiting for output..."
                      : "No output yet. Start an audit to fill this tab."
            }
        }
    }

    Connections {
        target: auditBackend
        function onLogChanged() {
            if (logTab.follow)
                logFlick.contentY = logFlick.contentHeight - logFlick.height
        }
    }
}
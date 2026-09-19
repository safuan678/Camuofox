import QtQuick
import QtQuick.Layouts
import "../theme"

Rectangle {
        default property alias content: col.children
        property string title: ""

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
                    text: title
                }
            }

            ColumnLayout {
                id: col
                Layout.fillWidth: true
                Layout.margins: Theme.s4
                spacing: Theme.s3
            }

            Item { Layout.fillHeight: true }
        }
}

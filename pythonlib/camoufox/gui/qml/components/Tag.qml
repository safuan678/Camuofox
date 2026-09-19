import QtQuick
import "../theme"

Rectangle {
        property alias text: lbl.text
        property color accent: Theme.ok

        width: lbl.width + Theme.s3
        height: Theme.row - Theme.s3
        radius: Theme.s1
        color: Qt.rgba(accent.r, accent.g, accent.b, 0.15)
        border.color: accent
        border.width: 1

        T {
            id: lbl
            anchors.centerIn: parent
            color: parent.accent
            font.capitalization: Font.Capitalize
        }
}

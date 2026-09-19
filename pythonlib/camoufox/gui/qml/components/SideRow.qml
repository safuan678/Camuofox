import QtQuick
import "../theme"

Rectangle {
        property bool sel: false
        property bool bar: false
        signal clicked

        width: parent ? parent.width : 0
        height: Theme.row
        color: sel ? Theme.raised : ma.containsMouse ? Theme.raised : "transparent"

        Rectangle {
            visible: bar && sel
            width: Theme.s1
            height: parent.height
            color: Theme.accent
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: parent.clicked()
        }
}

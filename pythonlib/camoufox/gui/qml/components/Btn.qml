import QtQuick
import "../theme"

Rectangle {
        property string text: ""
        property string icon: ""
        property bool on: true
        property color accent: Theme.text
        signal clicked

        width: _row.implicitWidth + Theme.s3
        height: Theme.row - Theme.s2
        radius: Theme.s1
        color: on && _ma.containsMouse ? Theme.raised : "transparent"
        border.color: Theme.border
        border.width: 1
        opacity: on ? 1 : 0.4

        Row {
            id: _row
            anchors.centerIn: parent
            spacing: (icon && text) ? Theme.s1 : 0

            Icon {
                visible: !!icon
                anchors.verticalCenter: parent.verticalCenter
                icon: _row.parent.icon
                color: _row.parent.on ? _row.parent.accent : Theme.muted
            }

            T {
                visible: !!text
                anchors.verticalCenter: parent.verticalCenter
                text: _row.parent.text
                color: _row.parent.on ? _row.parent.accent : Theme.muted
            }
        }

        MouseArea {
            id: _ma
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: on ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: if (parent.on) parent.clicked()
        }
}

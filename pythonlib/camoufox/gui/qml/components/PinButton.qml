import QtQuick
import QtQuick.Controls
import "../theme"

Item {
        id: pinButton
        property bool pinned: false
        property string pinToolTip: "Pin version"
        property string unpinToolTip: "Unpin version"
        signal clicked

        width: Theme.s4
        height: Theme.s4

        Icon {
            anchors.centerIn: parent
            icon: "\uE840"
            color: pinButton.pinned ? Theme.accent : Theme.muted
            opacity: pinButton.enabled ? 1 : 0.4
        }

        Icon {
            anchors.centerIn: parent
            icon: "\uE842"
            color: Theme.accent
            opacity: pinButton.enabled ? 1 : 0.4
            visible: pinButton.pinned
        }

        MouseArea {
            id: pinMa
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: pinButton.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: if (pinButton.enabled) pinButton.clicked()
        }

        ToolTip.visible: pinMa.containsMouse && pinButton.enabled
        ToolTip.text: pinButton.pinned ? pinButton.unpinToolTip : pinButton.pinToolTip
        ToolTip.delay: 500
}

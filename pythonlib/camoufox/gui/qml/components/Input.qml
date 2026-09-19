import QtQuick
import "../theme"

Rectangle {
        property alias text: inp.text
        property alias input: inp
        property string placeholder: ""
        signal editingFinished

        width: Math.round(160 * Theme.scale)
        height: Theme.row - Theme.s2
        radius: Theme.s1
        color: Theme.raised
        border.color: inp.activeFocus ? Theme.accent : Theme.border
        border.width: 1

        TextInput {
            id: inp
            anchors.fill: parent
            leftPadding: Theme.s2
            rightPadding: Theme.s2
            color: Theme.text
            font.family: Theme.fontMain
            font.pixelSize: Theme.textSm
            verticalAlignment: Text.AlignVCenter
            onEditingFinished: parent.editingFinished()
        }

        Muted {
            anchors.left: parent.left
            anchors.leftMargin: Theme.s2
            anchors.verticalCenter: parent.verticalCenter
            text: placeholder
            visible: !inp.text && !inp.activeFocus
        }
}

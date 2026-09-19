import QtQuick
import QtQuick.Controls
import "../theme"

ComboBox {
        id: cb
        implicitWidth: Theme.colW
        implicitHeight: Theme.row - Theme.s2

        background: Rectangle {
            color: Theme.raised
            radius: Theme.s1
            border.color: Theme.border
            border.width: 1
        }

        contentItem: T {
            text: cb.displayText
            leftPadding: Theme.s2
            verticalAlignment: Text.AlignVCenter
        }

        delegate: ItemDelegate {
            required property int index
            required property string modelData
            width: cb.width
            height: Theme.row - Theme.s2
            contentItem: T {
                text: modelData
                verticalAlignment: Text.AlignVCenter
            }
            background: Rectangle {
                color: highlighted ? Theme.raised : Theme.fg
            }
        }
}

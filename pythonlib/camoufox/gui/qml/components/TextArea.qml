import QtQuick
import QtQuick.Controls
import "../theme"

//: Multi-line sibling of Input, for the settings that take a list: extra paths
//: and custom headers. A single-line field would silently collapse "one per
//: line" into one unusable line, which is the whole reason this exists.
Rectangle {
    property alias text: area.text
    property alias area: area
    property string placeholder: ""

    width: Math.round(160 * Theme.scale)
    height: Math.round(64 * Theme.scale)
    radius: Theme.s1
    color: Theme.raised
    border.color: area.activeFocus ? Theme.accent : Theme.border
    border.width: 1

    Flickable {
        id: scroller
        anchors.fill: parent
        anchors.margins: Theme.s1
        clip: true
        contentWidth: width
        contentHeight: area.implicitHeight
        boundsBehavior: Flickable.StopAtBounds

        TextArea {
            id: area
            width: scroller.width
            color: Theme.text
            font.family: Theme.fontMain
            font.pixelSize: Theme.textSm
            wrapMode: TextArea.WrapAtWordBoundaryOrAnywhere
            background: null
            padding: Theme.s1
        }
    }

    Muted {
        anchors.left: parent.left
        anchors.leftMargin: Theme.s2
        anchors.top: parent.top
        anchors.topMargin: Theme.s2
        text: placeholder
        visible: !area.text && !area.activeFocus
    }
}
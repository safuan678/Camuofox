import QtQuick
import "../theme"

Text {
        property string icon: ""
        text: icon
        color: Theme.text
        font.family: Theme.fontIcon
        font.pixelSize: Theme.textSm
}

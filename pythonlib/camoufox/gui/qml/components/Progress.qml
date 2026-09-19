import QtQuick
import "../theme"

Rectangle {
        id: _bar
        property real value: -1
        property bool active: false

        height: Theme.s1
        radius: Theme.s1 / 2
        color: Theme.raised

        Rectangle {
            id: _fill
            x: 0
            width: _bar.value >= 0 ? _bar.width * _bar.value : _bar.width * 0.3
            height: parent.height
            radius: parent.radius
            color: Theme.accent
        }

        Timer {
            interval: 16; repeat: true
            running: _bar.active && _bar.value < 0
            property real pos: 0
            property bool fwd: true
            onTriggered: {
                if (fwd) { pos += 0.02; if (pos >= 0.7) fwd = false }
                else { pos -= 0.02; if (pos <= 0) fwd = true }
                _fill.x = _bar.width * pos
            }
            onRunningChanged: if (!running) { pos = 0; _fill.x = 0 }
        }
}

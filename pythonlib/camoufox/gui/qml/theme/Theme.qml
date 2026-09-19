pragma Singleton
import QtQuick

//: Single source of truth for colours, metrics and fonts.
//:
//: Every panel, tab and component reads its colours and sizes from here, so the
//: scale slider adjusts the whole interface from one value and a palette change
//: cannot leave half the app behind. The font loaders live here too: a
//: FontLoader inside a singleton loads once for the process rather than once
//: per file that had to declare its own.
Item {
    // 4pt spacing scale
    property real scale: 1.0
    readonly property int row: Math.round(32 * scale)
    readonly property int s1: Math.round(4 * scale)
    readonly property int s2: Math.round(8 * scale)
    readonly property int s3: Math.round(12 * scale)
    readonly property int s4: Math.round(16 * scale)
    readonly property int textSm: Math.round(12 * scale)
    readonly property int textMd: Math.round(14 * scale)
    readonly property int textLg: Math.round(20 * scale)
    readonly property int colW: Math.round(100 * scale)
    readonly property int verColW: Math.round(70 * scale)
    readonly property int dateColW: Math.round(90 * scale)

    readonly property string fontMain: segoe.name
    readonly property string fontIcon: mdl2.name

    readonly property color bg: "#181818"
    readonly property color fg: "#1f1f1f"
    readonly property color raised: "#282828"
    readonly property color border: "#383838"
    readonly property color text: "#ffffff"
    readonly property color muted: "#a0a0a0"
    readonly property color dim: "#606060"
    readonly property color accent: "#569cd6"
    readonly property color ok: "#6b9e7e"
    readonly property color err: "#f14c4c"
    //: Painted behind a live/pass state, matching the ok/err foregrounds.
    readonly property color okBg: "#1e2a1e"
    readonly property color errBg: "#2a1e1e"

    FontLoader { id: segoe; source: "../../assets/SegUIVar.ttf" }
    FontLoader { id: mdl2; source: "../../assets/segmdl2.ttf" }
}

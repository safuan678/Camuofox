import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "theme"
import "components"

ApplicationWindow {
    id: root
    visible: true
    width: 800
    height: 520
    minimumWidth: 640
    minimumHeight: 400
    title: "Camoufox Manager"
    color: Theme.bg

    //: UI scale. Theme owns every metric derived from it, so assigning here
    //: resizes the whole interface; the debug slider below is the only writer.
    property real scale: 1.0
    Binding { target: Theme; property: "scale"; value: root.scale }

    property string geoipDlgSource: ""

    // Primitives live in components/; see theme/Theme.qml for colours and sizes.


    // Dialog

    property string dlgAct: ""
    property string dlgVer: ""
    property string dlgBuild: ""
    property string dlgChannel: ""
    property int dlgIdx: -1

    function showDlg(act, idx, ver, build, channel) {
        backend.selectVersion(idx)
        dlgAct = act
        dlgIdx = idx
        dlgVer = ver
        dlgBuild = build
        dlgChannel = channel || ""
    }

    Rectangle {
        anchors.fill: parent
        color: "#80000000"
        visible: dlgAct !== ""
        z: 100
        MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            onClicked: dlgAct = ""
        }
    }

    Rectangle {
        visible: dlgAct !== ""
        anchors.centerIn: parent
        width: Math.round(340 * Theme.scale)
        height: dlgContent.height + Theme.s4 * 2
        color: Theme.fg
        border.color: Theme.border
        radius: Theme.s2
        z: 101

        Column {
            id: dlgContent
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: Theme.s4
            spacing: Theme.s3

            Bold {
                text: (dlgAct === "install" || dlgAct === "promptInstall") ? "Install"
                     : dlgAct === "uninstall" ? "Uninstall"
                     : dlgAct === "promptPin" ? "Pin Version"
                     : dlgAct === "promptFollow" ? "Follow Channel" : "Set Active"
                font.pixelSize: Theme.textMd
            }

            T {
                width: parent.width
                wrapMode: Text.Wrap
                text: dlgAct === "promptInstall"
                    ? "Camoufox " + dlgVer + "-" + dlgBuild + " is now active but not installed. Install it now?"
                    : dlgAct === "promptPin"
                    ? "Camoufox " + dlgVer + "-" + dlgBuild + " is installed but not active. Would you like to pin this version?"
                    : dlgAct === "promptFollow"
                    ? "Camoufox " + dlgVer + "-" + dlgBuild + " is installed but not active. Would you like to follow " + dlgChannel + " for updates?"
                    : (dlgAct === "install" ? "Install" : dlgAct === "uninstall" ? "Remove" : "Set") +
                      " Camoufox " + dlgVer + "-" + dlgBuild +
                      (dlgAct === "install" ? "?" : dlgAct === "uninstall" ? " from disk?" : " as active?")
            }

            T {
                visible: (dlgAct === "install" || dlgAct === "promptInstall") && backend.selectedIsPrerelease
                width: parent.width
                color: Theme.err
                wrapMode: Text.Wrap
                text: "Warning: Prerelease versions may be unstable."
            }

            Item { width: 1; height: Theme.s1 }

            Row {
                anchors.right: parent.right
                spacing: Theme.s2

                Btn {
                    text: (dlgAct === "promptInstall" || dlgAct === "promptPin" || dlgAct === "promptFollow") ? "Skip" : "Cancel"
                    onClicked: dlgAct = ""
                }

                Btn {
                    visible: dlgAct === "promptFollow"
                    text: "Pin Version"
                    accent: Theme.accent
                    onClicked: {
                        backend.setActive(dlgIdx)
                        dlgAct = ""
                    }
                }

                Btn {
                    text: (dlgAct === "install" || dlgAct === "promptInstall") ? "Install"
                        : dlgAct === "uninstall" ? "Uninstall"
                        : dlgAct === "promptPin" ? "Pin Version"
                        : dlgAct === "promptFollow" ? "Follow Channel" : "Set Active"
                    accent: dlgAct === "uninstall" ? Theme.err
                        : (dlgAct === "install" || dlgAct === "promptInstall") ? Theme.ok : Theme.accent
                    onClicked: {
                        if (dlgAct === "install" || dlgAct === "promptInstall") {
                            backend.installSelected()
                        } else if (dlgAct === "uninstall") {
                            backend.uninstallSelected()
                        } else if (dlgAct === "promptPin") {
                            backend.setActive(dlgIdx)
                        } else if (dlgAct === "promptFollow") {
                            backend.followVersionChannel(dlgIdx)
                        } else if (dlgAct === "channel") {
                            backend.confirmFollowChannel()
                            if (backend.canInstall) {
                                dlgAct = "promptInstall"
                                return
                            }
                        } else {
                            backend.setActive(dlgIdx)
                            backend.selectVersion(dlgIdx)
                            if (backend.canInstall) {
                                dlgAct = "promptInstall"
                                return
                            }
                        }
                        dlgAct = ""
                    }
                }
            }
        }
    }

    Connections {
        target: backend
        function onCurrentRepoChanged() {
            repoList.currentIndex = backend.currentRepoIndex
        }
        function onChannelPrompt(idx, display, build) {
            showDlg("channel", idx, display, build)
        }
        function onInstalledPrompt(idx, display, build, latest, channel) {
            showDlg(latest ? "promptFollow" : "promptPin", idx, display, build, channel)
        }
    }

    // Layout

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Tab bar
        Rectangle {
            Layout.fillWidth: true
            height: Theme.row
            color: Theme.fg

            Rule { anchors.bottom: parent.bottom }

            Row {
                anchors.left: parent.left
                anchors.leftMargin: Theme.s3
                anchors.verticalCenter: parent.verticalCenter

                Repeater {
                    model: ["Browsers", "GeoIP", "Info", "Audit"]

                    Rectangle {
                        width: tabLbl.width + Theme.s4 * 2
                        height: Theme.row
                        color: "transparent"

                        T {
                            id: tabLbl
                            anchors.centerIn: parent
                            text: modelData
                            color: tabs.currentIndex === index ? Theme.accent : Theme.muted
                        }

                        Rectangle {
                            anchors.bottom: parent.bottom
                            width: parent.width
                            height: Theme.s1 / 2
                            color: Theme.accent
                            visible: tabs.currentIndex === index
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: tabs.currentIndex = index
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Sidebar
            Rectangle {
                Layout.preferredWidth: Math.round(210 * Theme.scale)
                Layout.fillHeight: true
                color: Theme.fg
                visible: tabs.currentIndex === 0

                Rectangle {
                    anchors.right: parent.right
                    width: 1
                    height: parent.height
                    color: Theme.border
                }

                Column {
                    anchors.top: parent.top
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.rightMargin: 1

                    Rectangle {
                        width: parent.width
                        height: Theme.row
                        color: "transparent"

                        Header {
                            anchors.left: parent.left
                            anchors.leftMargin: Theme.s3
                            anchors.verticalCenter: parent.verticalCenter
                            text: "REPOSITORIES"
                        }
                    }

                    ListView {
                        id: repoList
                        width: parent.width
                        height: contentHeight
                        interactive: false
                        model: backend.repos

                        delegate: SideRow {
                            sel: ListView.isCurrentItem
                            bar: true

                            T {
                                anchors.left: parent.left
                                anchors.leftMargin: Theme.s4
                                anchors.verticalCenter: parent.verticalCenter
                                text: modelData
                            }

                            onClicked: {
                                repoList.currentIndex = index
                                backend.selectRepo(index)
                            }
                        }

                        Component.onCompleted: backend.selectRepo(0)
                    }

                    Rule {}

                    Rectangle {
                        width: parent.width
                        height: Theme.row
                        color: "transparent"

                        Header {
                            anchors.left: parent.left
                            anchors.leftMargin: Theme.s3
                            anchors.verticalCenter: parent.verticalCenter
                            text: "FOLLOW CHANNEL"
                        }
                    }

                    Repeater {
                        model: backend.channels

                        Rectangle {
                            width: parent ? parent.width : 0
                            height: Theme.row + Theme.s2
                            color: chMa.containsMouse ? Theme.raised : "transparent"

                            Column {
                                anchors.left: parent.left
                                anchors.leftMargin: Theme.s4
                                anchors.right: parent.right
                                anchors.rightMargin: Theme.s3
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: 1

                                Row {
                                    spacing: Theme.s2
                                    PinButton {
                                        pinned: backend.followedChannel === backend.channelKeys[index]
                                        pinToolTip: "Follow channel"
                                        unpinToolTip: "Following channel"
                                        anchors.verticalCenter: parent.verticalCenter
                                        onClicked: backend.setFollowedChannel(index)
                                    }
                                    T { text: (backend.followedChannel === backend.channelKeys[index] ? "Following " : "Follow ") + modelData; anchors.verticalCenter: parent.verticalCenter }
                                }

                                Muted {
                                    leftPadding: Theme.s4 + Theme.s2
                                    text: backend.channelLatest[index] ? ("Latest: " + backend.channelLatest[index]) : "(sync first)"
                                    font.pixelSize: Math.round(10 * Theme.scale)
                                }
                            }

                            MouseArea {
                                id: chMa
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: backend.setFollowedChannel(index)
                            }
                        }
                    }
                }

            }

            StackLayout {
                id: tabs
                Layout.fillWidth: true
                Layout.fillHeight: true

                // Browsers
                Rectangle {
                    color: Theme.bg

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0

                        Rectangle {
                            Layout.fillWidth: true
                            height: Theme.row
                            color: Theme.fg

                            Rule { anchors.bottom: parent.bottom }

                            Row {
                                anchors.left: parent.left
                                anchors.leftMargin: Theme.s3
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Theme.s3

                                Rectangle {
                                    width: Theme.s3
                                    height: Theme.s3
                                    radius: Theme.s1
                                    color: "transparent"
                                    border.color: Theme.dim
                                    border.width: 1
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Header {
                                    text: "VERSION"
                                    width: Theme.verColW
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Header {
                                    text: "BUILD"
                                    width: Theme.verColW
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Header {
                                    text: "DATE"
                                    width: Theme.dateColW
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Header {
                                    text: "STATUS"
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                            }
                        }

                        ListView {
                            id: vList
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            model: backend.versionModel

                            property real scrollBarWidth: vScrollBar.visible ? vScrollBar.width : 0

                            ScrollBar.vertical: ScrollBar {
                                id: vScrollBar
                                policy: vList.contentHeight > vList.height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff
                                contentItem: Rectangle {
                                    implicitWidth: Theme.s2
                                    radius: Theme.s1
                                    color: Theme.border
                                }
                            }

                            delegate: Rectangle {
                                id: vrow
                                property bool hov: hover.hovered

                                width: vList.width - vList.scrollBarWidth
                                height: Theme.row
                                color: model.isHeader ? Theme.fg :
                                       model.isPinned ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.06) :
                                       hov ? Qt.rgba(1, 1, 1, 0.02) : "transparent"

                                Rectangle {
                                    anchors.top: parent.top
                                    width: parent.width
                                    height: 1
                                    color: model.isHeader && index > 0 ? Theme.border : "transparent"
                                }

                                Rectangle {
                                    anchors.bottom: parent.bottom
                                    width: parent.width
                                    height: 1
                                    color: model.isHeader ? Theme.border : "transparent"
                                }

                                Rectangle {
                                    width: Theme.s1
                                    height: parent.height
                                    color: model.isPinned && !model.isHeader ? Theme.accent : "transparent"
                                }

                                HoverHandler { id: hover }

                                Bold {
                                    anchors.left: parent.left
                                    anchors.leftMargin: Theme.s3
                                    anchors.verticalCenter: parent.verticalCenter
                                    visible: model.isHeader
                                    text: model.display
                                }

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: Theme.s3
                                    anchors.rightMargin: Theme.s2
                                    spacing: Theme.s3
                                    visible: !model.isHeader

                                    PinButton {
                                        pinned: model.isPinned
                                        enabled: model.note === ""
                                        onClicked: {
                                            if (model.isPinned) {
                                                backend.unpinVersion(index)
                                            } else {
                                                showDlg("setActive", index, model.display, model.build)
                                            }
                                        }
                                    }

                                    T {
                                        text: model.display
                                        color: model.isInstalled ? Theme.text : Theme.dim
                                        Layout.preferredWidth: Theme.verColW
                                    }

                                    T {
                                        text: model.build
                                        color: model.isInstalled ? Theme.text : Theme.dim
                                        Layout.preferredWidth: Theme.verColW
                                    }

                                    T {
                                        text: model.date
                                        color: model.isInstalled ? Theme.text : Theme.dim
                                        Layout.preferredWidth: Theme.dateColW
                                    }

                                    Row {
                                        spacing: Theme.s2
                                        Layout.fillWidth: true

                                        Tag {
                                            visible: model.isInstalled
                                            text: "installed"
                                        }

                                        Tag {
                                            visible: model.isActive
                                            text: "active"
                                            accent: Theme.accent
                                        }

                                        Tag {
                                            visible: model.note !== ""
                                            text: model.note
                                        }
                                    }

                                    Btn {
                                        visible: vrow.hov && !model.isInstalled
                                        icon: "\uE896"
                                        text: "Download"
                                        accent: Theme.ok
                                        on: !backend.busy
                                        onClicked: showDlg("install", index, model.display, model.build)
                                    }

                                    Btn {
                                        visible: vrow.hov && model.isInstalled
                                        icon: "\uE74D"
                                        text: "Delete"
                                        accent: Theme.err
                                        on: !backend.busy
                                        onClicked: showDlg("uninstall", index, model.display, model.build)
                                    }
                                }
                            }
                        }

                    }
                }

                // GeoIP
                Rectangle {
                    color: Theme.bg

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 0

                        Rectangle {
                            Layout.fillWidth: true
                            height: Theme.row
                            color: Theme.fg

                            Rule { anchors.bottom: parent.bottom }

                            Header {
                                anchors.left: parent.left
                                anchors.leftMargin: Theme.s3
                                anchors.verticalCenter: parent.verticalCenter
                                text: "GEOIP DATABASE"
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            visible: !backend.geoipAvailable
                            height: visible ? notInstalledCol.height + Theme.s4 * 2 : 0
                            color: Theme.fg

                            ColumnLayout {
                                id: notInstalledCol
                                anchors.centerIn: parent
                                spacing: Theme.s2

                                T {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "IP Geolocation support is missing."
                                    font.pixelSize: Theme.textMd
                                }

                                T {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: "Run: pip install camoufox[geoip]"
                                    color: Theme.muted
                                    font.family: root.Theme.fontMain
                                }
                            }
                        }

                        Column {
                            Layout.fillWidth: true
                            visible: backend.geoipAvailable
                            spacing: 0

                            Repeater {
                                model: backend.geoipSources

                                Rectangle {
                                    id: geoRow
                                    property bool hov: geoHover.hovered
                                    property bool active: backend.geoipInstalled === modelData
                                    property bool downloaded: backend.geoipDownloaded.indexOf(modelData) >= 0

                                    width: parent.width
                                    height: Theme.row
                                    color: active ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.06) :
                                           hov ? Qt.rgba(1, 1, 1, 0.02) : "transparent"

                                    Rectangle {
                                        width: Theme.s1
                                        height: parent.height
                                        color: geoRow.active ? Theme.accent : "transparent"
                                    }

                                    HoverHandler { id: geoHover }

                                    MouseArea {
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: {
                                            if (backend.geoipBusy) return
                                            if (!geoRow.downloaded) {
                                                root.geoipDlgSource = modelData
                                            } else if (!geoRow.active) {
                                                backend.setActiveGeoip(modelData)
                                            }
                                        }
                                    }

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: Theme.s3
                                        anchors.rightMargin: Theme.s3
                                        spacing: Theme.s3

                                        T {
                                            text: modelData
                                            color: geoRow.downloaded ? Theme.text : Theme.dim
                                            Layout.fillWidth: true
                                        }

                                        Tag {
                                            visible: geoRow.active
                                            text: "active"
                                            accent: Theme.accent
                                        }

                                        Btn {
                                            visible: geoRow.hov && !geoRow.downloaded
                                            icon: "\uE896"
                                            text: "Download"
                                            accent: Theme.ok
                                            on: !backend.geoipBusy
                                            onClicked: root.geoipDlgSource = modelData
                                        }

                                        Btn {
                                            visible: geoRow.hov && geoRow.downloaded && !geoRow.active
                                            icon: "\uE74D"
                                            text: "Delete"
                                            accent: Theme.err
                                            on: !backend.geoipBusy
                                            onClicked: backend.deleteGeoipSource(modelData)
                                        }
                                    }
                                }
                            }
                        }

                        Rule { Layout.fillWidth: true; Layout.topMargin: Theme.s3; visible: backend.geoipAvailable }

                        // IP Lookup
                        ColumnLayout {
                            visible: backend.geoipAvailable
                            Layout.fillWidth: true
                            Layout.margins: Theme.s4
                            spacing: Theme.s2

                            Bold { text: "IP Lookup" }

                            Row {
                                spacing: Theme.s2

                                Input {
                                    id: ipIn
                                    placeholder: "Enter IP..."
                                    input.onAccepted: backend.lookupIp(text)
                                }

                                Btn {
                                    text: "Lookup"
                                    onClicked: backend.lookupIp(ipIn.text)
                                }
                            }

                            T {
                                visible: backend.lookupResult.length > 0
                                text: backend.lookupResult
                                textFormat: Text.RichText
                                color: backend.lookupSuccess ? Theme.ok : Theme.err
                            }
                        }

                        Item { Layout.fillHeight: true }

                        Rectangle {
                            Layout.fillWidth: true
                            visible: backend.geoipInstalled.length > 0 || backend.geoipBusy
                            height: visible ? metaCol.height + Theme.s4 * 2 : 0
                            color: Theme.fg

                            Rule { anchors.top: parent.top }

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: Theme.s4
                                spacing: Theme.s4

                                Column {
                                    id: metaCol
                                    Layout.fillWidth: true
                                    spacing: Theme.s1

                                    Row {
                                        spacing: Theme.s2
                                        Muted { text: "Path:" }
                                        T { text: backend.geoipPath }
                                    }

                                    Row {
                                        spacing: Theme.s2
                                        Muted { text: "Size:" }
                                        T { text: backend.geoipSize }
                                    }

                                    Row {
                                        spacing: Theme.s2
                                        Muted { text: "Downloaded:" }
                                        T { text: backend.geoipMtime }
                                    }
                                }

                                Btn {
                                    icon: "\uE72C"
                                    accent: Theme.accent
                                    on: !backend.geoipBusy && backend.geoipInstalled.length > 0
                                    onClicked: backend.refreshGeoip()
                                }

                                Btn {
                                    icon: "\uE838"
                                    accent: Theme.text
                                    on: backend.geoipInstalled.length > 0
                                    onClicked: backend.openGeoipFolder()
                                }

                                Btn {
                                    icon: "\uE74D"
                                    accent: Theme.err
                                    on: !backend.geoipBusy && backend.geoipInstalled.length > 0
                                    onClicked: backend.deleteGeoipData()
                                }
                            }
                        }

                        Progress {
                            Layout.fillWidth: true
                            visible: backend.geoipBusy
                            height: Theme.s2
                            radius: 0
                            value: backend.geoipProgress
                            active: backend.geoipBusy
                        }
                    }

                    // GeoIP download dialog
                    Rectangle {
                        anchors.fill: parent
                        color: "#80000000"
                        visible: root.geoipDlgSource !== ""
                        z: 100

                        MouseArea {
                            anchors.fill: parent
                            hoverEnabled: true
                            onClicked: root.geoipDlgSource = ""
                        }
                    }

                    Rectangle {
                        visible: root.geoipDlgSource !== ""
                        anchors.centerIn: parent
                        width: Math.round(320 * Theme.scale)
                        height: Math.round(140 * Theme.scale)
                        color: Theme.fg
                        border.color: Theme.border
                        radius: Theme.s2
                        z: 101

                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: Theme.s4
                            spacing: Theme.s3

                            Bold {
                                text: "Download GeoIP Database"
                                font.pixelSize: Theme.textMd
                            }

                            T {
                                Layout.fillWidth: true
                                wrapMode: Text.Wrap
                                text: "Download " + root.geoipDlgSource + " database? This will download both IPv4 and IPv6 files."
                            }

                            Item { Layout.fillHeight: true }

                            Row {
                                Layout.alignment: Qt.AlignRight
                                spacing: Theme.s2

                                Btn {
                                    text: "Cancel"
                                    onClicked: root.geoipDlgSource = ""
                                }

                                Btn {
                                    text: "Download"
                                    accent: Theme.ok
                                    onClicked: {
                                        backend.downloadGeoip(root.geoipDlgSource)
                                        root.geoipDlgSource = ""
                                    }
                                }
                            }
                        }
                    }
                }

                // Info
                Section {
                    title: "SYSTEM INFO"

                    GridLayout {
                        columns: 2
                        columnSpacing: Theme.s4 * 2
                        rowSpacing: Theme.s2

                        Muted { text: backend.activeBrowserLabel }
                        Bold { text: backend.activeBrowserText; color: backend.activeBrowserColor }

                        Muted { text: "Python Library" }
                        T { text: backend.libraryVersion }

                        Muted { text: "Playwright" }
                        T { text: backend.playwrightVersion }

                        Muted { text: "Browserforge" }
                        T { text: backend.browserforgeVersion }

                        Muted { text: "Fingerprints" }
                        T { text: backend.fingerprintVersion }

                        Muted { text: "Last Sync" }
                        T { text: backend.lastSyncTime || "Never" }

                        Muted { text: "Website" }
                        T {
                            text: "<a href='https://camoufox.com' style='color:" + Theme.accent + "'>camoufox.com</a>"
                            textFormat: Text.RichText
                            onLinkActivated: link => Qt.openUrlExternally(link)
                        }
                    }

                    Rule { visible: debugMode }

                    Bold { text: "Debug Options"; visible: debugMode }

                    Row {
                        visible: debugMode
                        spacing: Theme.s4

                        Row {
                            spacing: Theme.s2
                            Muted { text: "Spoof OS"; anchors.verticalCenter: parent.verticalCenter }
                            Combo {
                                model: backend.spoofOsOptions
                                currentIndex: backend.spoofOsIndex
                                onActivated: backend.setSpoofOs(currentIndex)
                                implicitWidth: Math.round(90 * Theme.scale)
                            }
                        }

                        Row {
                            spacing: Theme.s2
                            Muted { text: "Spoof Arch"; anchors.verticalCenter: parent.verticalCenter }
                            Combo {
                                model: backend.spoofArchOptions
                                currentIndex: backend.spoofArchIndex
                                onActivated: backend.setSpoofArch(currentIndex)
                                implicitWidth: Math.round(90 * Theme.scale)
                            }
                        }

                        Row {
                            spacing: Theme.s2
                            Muted { text: "Lib Version"; anchors.verticalCenter: parent.verticalCenter }
                            Rectangle {
                                width: Math.round(80 * Theme.scale)
                                height: Math.round(24 * Theme.scale)
                                color: "#1affffff"
                                radius: Math.round(3 * Theme.scale)
                                TextInput {
                                    anchors.fill: parent
                                    anchors.margins: Math.round(4 * Theme.scale)
                                    color: "#fff"
                                    font.pixelSize: Math.round(11 * Theme.scale)
                                    text: backend.spoofLibVer
                                    verticalAlignment: TextInput.AlignVCenter
                                    clip: true
                                    selectByMouse: true
                                    property string placeholder: "(auto)"
                                    Text {
                                        text: parent.placeholder
                                        color: "#80ffffff"
                                        font: parent.font
                                        visible: !parent.text && !parent.activeFocus
                                        anchors.verticalCenter: parent.verticalCenter
                                    }
                                    onEditingFinished: backend.setSpoofLibVer(text)
                                }
                            }
                        }
                    }


                    Rule { visible: debugMode }

                    Row {
                        visible: debugMode
                        spacing: Theme.s3

                        Muted { text: "UI Scale"; anchors.verticalCenter: parent.verticalCenter }

                        Slider {
                            id: scaleSlider
                            from: 0.8
                            to: 1.5
                            stepSize: 0.1
                            value: root.scale
                            onPressedChanged: if (!pressed) root.scale = value
                            implicitWidth: Math.round(140 * Theme.scale)
                            implicitHeight: Theme.row - Theme.s2

                            background: Rectangle {
                                x: scaleSlider.leftPadding
                                y: scaleSlider.topPadding + scaleSlider.availableHeight / 2 - Theme.s1 / 2
                                width: scaleSlider.availableWidth
                                height: Theme.s1
                                radius: Theme.s1 / 2
                                color: Theme.raised

                                Rectangle {
                                    width: scaleSlider.visualPosition * parent.width
                                    height: Theme.s1
                                    radius: Theme.s1 / 2
                                    color: Theme.accent
                                }
                            }

                            handle: Rectangle {
                                x: scaleSlider.leftPadding + scaleSlider.visualPosition * (scaleSlider.availableWidth - width)
                                y: scaleSlider.topPadding + scaleSlider.availableHeight / 2 - height / 2
                                width: Theme.s4
                                height: Theme.s4
                                radius: Theme.s2
                                color: scaleSlider.pressed ? Theme.accent : Theme.text
                            }
                        }

                        T { text: Math.round(scaleSlider.value * 100) + "%" }
                    }
                }

                // Audit
                Rectangle {
                    color: Theme.bg

                    RowLayout {
                        anchors.fill: parent
                        spacing: 0

                        // ---- left: configuration ----
                        Rectangle {
                            Layout.preferredWidth: Math.round(330 * Theme.scale)
                            Layout.fillHeight: true
                            color: Theme.bg

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0

                                Rectangle {
                                    Layout.fillWidth: true
                                    height: Theme.row
                                    color: Theme.fg
                                    Rule { anchors.bottom: parent.bottom }
                                    Header {
                                        anchors.left: parent.left
                                        anchors.leftMargin: Theme.s3
                                        anchors.verticalCenter: parent.verticalCenter
                                        text: "AUDIT TARGET"
                                    }
                                }

                                Flickable {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    contentHeight: cfgCol.implicitHeight + Theme.s4
                                    clip: true
                                    boundsBehavior: Flickable.StopAtBounds

                                    ColumnLayout {
                                        id: cfgCol
                                        width: parent.width
                                        spacing: Theme.s2
                                        anchors.margins: Theme.s3

                                        Item { Layout.preferredHeight: Theme.s1 }

                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: "Only audit a site you own or have written permission to test."
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "TARGET URL"
                                        }
                                        Input {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            placeholder: "https://staging.example.com/"
                                            Component.onCompleted: text = auditBackend.target
                                            onTextChanged: auditBackend.setTarget(text)
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "AUTHORIZED HOSTS"
                                        }
                                        Input {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            placeholder: "example.com"
                                            Component.onCompleted: text = auditBackend.scopeHosts
                                            onTextChanged: auditBackend.setScopeHosts(text)
                                        }
                                        RowLayout {
                                            Layout.leftMargin: Theme.s3
                                            spacing: Theme.s2
                                            CheckBox {
                                                id: subdomainsBox
                                                text: "Include subdomains"
                                                checked: auditBackend.allowSubdomains
                                                onToggled: auditBackend.setAllowSubdomains(checked)
                                            }
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "OUTBOUND FUNNEL (PROMOTIONAL BANNERS)"
                                        }
                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: "Follow promotional banners the audited page actually serves, and record click-through and landing-page engagement. Only banners pointing at hosts below (or already in scope) are ever followed."
                                        }
                                        RowLayout {
                                            Layout.leftMargin: Theme.s3
                                            spacing: Theme.s2
                                            CheckBox {
                                                id: funnelBox
                                                text: "Audit banner click-throughs"
                                                checked: auditBackend.enableOutboundFunnel
                                                onToggled: auditBackend.setEnableOutboundFunnel(checked)
                                            }
                                        }
                                        RowLayout {
                                            Layout.leftMargin: Theme.s3
                                            spacing: Theme.s2
                                            visible: auditBackend.enableOutboundFunnel
                                            CheckBox {
                                                id: iframeBox
                                                text: "Inspect banners inside iframes"
                                                checked: auditBackend.includeIframes
                                                onToggled: auditBackend.setIncludeIframes(checked)
                                            }
                                        }
                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            visible: auditBackend.enableOutboundFunnel && !auditBackend.includeIframes
                                            text: "Main document only. Campaigns served from an ad iframe will not be discovered, and the funnel may report no banner on a page that is showing one."
                                        }
                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "PARTNER CAMPAIGN HOSTS"
                                            visible: auditBackend.enableOutboundFunnel
                                        }
                                        Input {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            visible: auditBackend.enableOutboundFunnel
                                            placeholder: "partner.example.net (optional)"
                                            Component.onCompleted: text = auditBackend.outboundHosts
                                            onTextChanged: auditBackend.setOutboundHosts(text)
                                        }
                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "CAMPAIGN INTERACTION RATE (%)"
                                            visible: auditBackend.enableOutboundFunnel
                                        }
                                        Input {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            visible: auditBackend.enableOutboundFunnel
                                            placeholder: "2.5"
                                            Component.onCompleted: text = auditBackend.campaignRatePct
                                            onTextChanged: auditBackend.setCampaignRatePct(text)
                                        }

                                        // Authorization gate
                                        Rectangle {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            implicitHeight: ackCol.implicitHeight + Theme.s3 * 2
                                            color: auditBackend.acknowledged ? "#1e2a1e" : "#2a1e1e"
                                            radius: Theme.s1
                                            border.color: auditBackend.acknowledged ? Theme.ok : Theme.err
                                            border.width: 1

                                            ColumnLayout {
                                                id: ackCol
                                                anchors.left: parent.left
                                                anchors.right: parent.right
                                                anchors.verticalCenter: parent.verticalCenter
                                                anchors.margins: Theme.s2
                                                spacing: Theme.s1

                                                CheckBox {
                                                    id: ackBox
                                                    text: "I am authorized to test this target"
                                                    checked: auditBackend.acknowledged
                                                    onToggled: auditBackend.setAcknowledged(checked)
                                                }
                                                Input {
                                                    Layout.fillWidth: true
                                                    placeholder: "Ticket / approval reference"
                                                    Component.onCompleted: text = auditBackend.acknowledgmentNote
                                                    onTextChanged: auditBackend.setAcknowledgmentNote(text)
                                                }
                                            }
                                        }

                                        Rule {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "TRAFFIC PLAN"
                                        }

                                        GridLayout {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            columns: 2
                                            columnSpacing: Theme.s2
                                            rowSpacing: Theme.s1

                                            Muted { text: "Visitors" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.visitors
                                                enabled: !auditBackend.singleLevelMode
                                                input.validator: IntValidator { bottom: 0; top: 1000000 }
                                                onEditingFinished: if (text.length) auditBackend.setVisitors(parseInt(text))
                                            }

                                            Muted { text: "Over (hours)" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.hours
                                                input.validator: DoubleValidator { bottom: 0.01; top: 8760 }
                                                onEditingFinished: if (text.length) auditBackend.setHours(parseFloat(text))
                                            }

                                            Muted { text: "Arrival pattern" }
                                            Combo {
                                                Layout.fillWidth: true
                                                model: auditBackend.patternOptions
                                                currentIndex: auditBackend.patternIndex
                                                onActivated: auditBackend.setPatternIndex(currentIndex)
                                            }

                                            Muted { text: "Max evasion level" }
                                            Combo {
                                                Layout.fillWidth: true
                                                model: ["0 - Naive HTTP", "1 - Headless", "2 - Headers", "3 - Fingerprint", "4 - Proxy rotation", "5 - Behavior", "6 - Persistent"]
                                                currentIndex: auditBackend.maxLevel
                                                enabled: !auditBackend.singleLevelMode
                                                onActivated: auditBackend.setMaxLevel(currentIndex)
                                            }

                                            Muted { text: "Single level" }
                                            Combo {
                                                Layout.fillWidth: true
                                                model: ["0 - Naive HTTP", "1 - Headless", "2 - Headers", "3 - Fingerprint", "4 - Proxy rotation", "5 - Behavior", "6 - Persistent"]
                                                currentIndex: auditBackend.singleLevel
                                                enabled: auditBackend.singleLevelMode
                                                onActivated: auditBackend.setSingleLevel(currentIndex)
                                            }

                                            Muted { text: "Seed (optional)" }
                                            Input {
                                                Layout.fillWidth: true
                                                placeholder: "random"
                                                Component.onCompleted: text = auditBackend.seed
                                                onTextChanged: auditBackend.setSeed(text)
                                            }
                                        }

                                        // Schedule preview
                                        Rectangle {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            implicitHeight: prevCol.implicitHeight + Theme.s3
                                            color: Theme.fg
                                            radius: Theme.s1
                                            border.color: Theme.border
                                            border.width: 1

                                            ColumnLayout {
                                                id: prevCol
                                                anchors.left: parent.left
                                                anchors.right: parent.right
                                                anchors.verticalCenter: parent.verticalCenter
                                                anchors.margins: Theme.s2
                                                spacing: Theme.s1

                                                Header { text: "ARRIVAL PREVIEW" }

                                                Row {
                                                    spacing: 2
                                                    Repeater {
                                                        model: auditBackend.schedulePreview
                                                        Rectangle {
                                                            width: Math.max(2, Math.round((prevCol.width - Theme.s4) / 24) - 2)
                                                            height: Math.max(3, Math.round(28 * (modelData / Math.max(1, auditBackend.maxPreview()))))
                                                            anchors.bottom: parent.bottom
                                                            color: Theme.accent
                                                            opacity: 0.35 + 0.65 * (modelData / Math.max(1, auditBackend.maxPreview()))
                                                        }
                                                    }
                                                }

                                                Muted {
                                                    Layout.fillWidth: true
                                                    wrapMode: Text.WordWrap
                                                    text: auditBackend.schedulePreviewSummary
                                                }
                                            }
                                        }

                                        Rule {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "PROXY"
                                        }

                                        GridLayout {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            columns: 2
                                            columnSpacing: Theme.s2
                                            rowSpacing: Theme.s1

                                            Muted { text: "Mode" }
                                            Combo {
                                                Layout.fillWidth: true
                                                model: auditBackend.proxyModeOptions
                                                currentIndex: auditBackend.proxyModeIndex
                                                onActivated: auditBackend.setProxyModeIndex(currentIndex)
                                            }

                                            Muted {
                                                visible: auditBackend.proxyModeIndex === 1
                                                text: "List file"
                                            }
                                            RowLayout {
                                                visible: auditBackend.proxyModeIndex === 1
                                                Layout.fillWidth: true
                                                spacing: Theme.s1
                                                Input {
                                                    id: proxyFileInput
                                                    Layout.fillWidth: true
                                                    placeholder: "/path/to/proxies.txt"
                                                    Component.onCompleted: text = auditBackend.proxyFile
                                                    onTextChanged: auditBackend.setProxyFile(text)
                                                }
                                                Btn {
                                                    text: "Browse"
                                                    onClicked: {
                                                        var r = auditBackend.browseProxyFile()
                                                        if (r.path) proxyFileInput.text = r.path
                                                        proxyStatus.text = r.message
                                                        proxyStatus.color = r.ok ? Theme.ok : Theme.err
                                                    }
                                                }
                                                Btn {
                                                    text: "Check"
                                                    onClicked: {
                                                        var r = auditBackend.validateProxyFile(proxyFileInput.text)
                                                        proxyStatus.text = r.message
                                                        proxyStatus.color = r.ok ? Theme.ok : Theme.err
                                                    }
                                                }
                                            }

                                            Muted {
                                                visible: auditBackend.proxyModeIndex === 2
                                                text: "Gateway"
                                            }
                                            Input {
                                                visible: auditBackend.proxyModeIndex === 2
                                                Layout.fillWidth: true
                                                placeholder: "http://user-session-{session}:pass@host:8000"
                                                Component.onCompleted: text = auditBackend.proxyGateway
                                                onTextChanged: auditBackend.setProxyGateway(text)
                                            }

                                            Muted {
                                                visible: auditBackend.proxyModeIndex === 1
                                                text: "Policy"
                                            }
                                            Combo {
                                                visible: auditBackend.proxyModeIndex === 1
                                                Layout.fillWidth: true
                                                model: auditBackend.proxyPolicyOptions
                                                currentIndex: auditBackend.proxyPolicyIndex
                                                onActivated: auditBackend.setProxyPolicyIndex(currentIndex)
                                            }

                                            Muted { text: "Per-proxy cap" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.maxPerProxy
                                                input.validator: IntValidator { bottom: 0; top: 100000 }
                                                onEditingFinished: if (text.length) auditBackend.setMaxPerProxy(parseInt(text))
                                            }
                                        }

                                        Muted {
                                            id: proxyStatus
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: ""
                                        }

                                        Rule {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                        }

                                        Header {
                                            Layout.leftMargin: Theme.s3
                                            text: "SAFETY CEILINGS"
                                        }
                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: "The audit stops when a ceiling is reached, rather than continuing."
                                        }

                                        GridLayout {
                                            Layout.leftMargin: Theme.s3
                                            Layout.rightMargin: Theme.s3
                                            Layout.fillWidth: true
                                            columns: 2
                                            columnSpacing: Theme.s2
                                            rowSpacing: Theme.s1

                                            Muted { text: "Max requests" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.maxRequests
                                                input.validator: IntValidator { bottom: 0; top: 100000000 }
                                                onEditingFinished: if (text.length) auditBackend.setMaxRequests(parseInt(text))
                                            }

                                            Muted { text: "Max requests/sec" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.maxRps
                                                input.validator: DoubleValidator { bottom: 0; top: 100000 }
                                                onEditingFinished: if (text.length) auditBackend.setMaxRps(parseFloat(text))
                                            }

                                            Muted { text: "Max concurrent" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.maxConcurrency
                                                input.validator: IntValidator { bottom: 1; top: 512 }
                                                onEditingFinished: if (text.length) auditBackend.setMaxConcurrency(parseInt(text))
                                            }

                                            Muted { text: "Max arrivals/min" }
                                            Input {
                                                Layout.fillWidth: true
                                                text: auditBackend.maxPerMinute
                                                input.validator: IntValidator { bottom: 1; top: 100000 }
                                                onEditingFinished: if (text.length) auditBackend.setMaxPerMinute(parseInt(text))
                                            }

                                            Muted { text: "Report directory" }
                                            Input {
                                                Layout.fillWidth: true
                                                placeholder: "optional"
                                                Component.onCompleted: text = auditBackend.outDir
                                                onTextChanged: auditBackend.setOutDir(text)
                                            }
                                        }

                                        CheckBox {
                                            Layout.leftMargin: Theme.s3
                                            text: "Single-level mode (run one rung, skip L0 up to it)"
                                            checked: auditBackend.singleLevelMode
                                            onToggled: auditBackend.setSingleLevelMode(checked)
                                        }

                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: "Off (default): the ladder runs from L0 up to the max "
                                                  + "level, which is what attributes a verdict to the control "
                                                  + "that holds. On: only the selected rung runs, with the "
                                                  + "visitor count pinned to 100 so repeat runs at that rung "
                                                  + "are comparable. A single rung cannot attribute a defense - "
                                                  + "the report says so."
                                        }

                                        CheckBox {
                                            Layout.leftMargin: Theme.s3
                                            text: "Force headless for every level"
                                            checked: auditBackend.headless
                                            onToggled: auditBackend.setHeadless(checked)
                                        }

                                        Muted {
                                            Layout.leftMargin: Theme.s3
                                            Layout.fillWidth: true
                                            wrapMode: Text.WordWrap
                                            text: "Off (default): each level runs the posture it "
                                                  + "defines - L1 headless, L2 and up headful - so the "
                                                  + "ladder isolates one control at a time. On: every "
                                                  + "browser level is forced headless, which is useful on "
                                                  + "a host that cannot show a window but merges L1 into "
                                                  + "the levels above it. The run says so when it overrides."
                                        }

                                        Item { Layout.preferredHeight: Theme.s2 }
                                    }
                                }
                            }
                        }

                        // ---- right: run + results ----
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.bg

                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0

                                // Run bar
                                Rectangle {
                                    Layout.fillWidth: true
                                    height: Theme.row
                                    color: Theme.fg
                                    Rule { anchors.bottom: parent.bottom }

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: Theme.s3
                                        anchors.rightMargin: Theme.s3
                                        spacing: Theme.s2

                                        Btn {
                                            text: "Start audit"
                                            icon: "\uE768"
                                            accent: auditBackend.canRun ? Theme.accent : Theme.muted
                                            on: auditBackend.canRun
                                            onClicked: auditBackend.start()
                                        }

                                        Btn {
                                            text: "Stop"
                                            accent: Theme.err
                                            on: auditBackend.running
                                            onClicked: auditBackend.stop()
                                        }

                                        Btn {
                                            text: "Clear"
                                            on: !auditBackend.running
                                            onClicked: auditBackend.clearResults()
                                        }

                                        Item { Layout.fillWidth: true }

                                        T {
                                            visible: auditBackend.running
                                            text: "running..."
                                            color: Theme.accent
                                        }

                                        T {
                                            visible: auditBackend.error.length > 0
                                            text: auditBackend.error
                                            color: Theme.err
                                            Layout.maximumWidth: Math.round(320 * Theme.scale)
                                            elide: Text.ElideRight
                                        }
                                    }
                                }

                                // Summary strip
                                Rectangle {
                                    Layout.fillWidth: true
                                    visible: !!auditBackend.summary
                                             && auditBackend.summary.visits !== undefined
                                    implicitHeight: sumRow.implicitHeight + Theme.s2
                                    color: Theme.fg

                                    RowLayout {
                                        id: sumRow
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        anchors.margins: Theme.s3
                                        spacing: Theme.s4

                                        T {
                                            text: "Visits: " + (auditBackend.summary.visits || 0)
                                        }
                                        T {
                                            text: "Requests: " + (auditBackend.summary.requests || 0)
                                        }
                                        T {
                                            text: "Duration: " + (auditBackend.summary.duration || 0) + "s"
                                        }
                                        T {
                                            visible: auditBackend.summary.aborted === true
                                            text: "ABORTED"
                                            color: Theme.err
                                        }
                                        Item { Layout.fillWidth: true }
                                    }
                                }

                                // Findings
                                Rectangle {
                                    Layout.fillWidth: true
                                    visible: auditBackend.findings.length > 0
                                    implicitHeight: Math.min(
                                        Math.round(150 * Theme.scale),
                                        findCol.implicitHeight + Theme.s3)
                                    color: Theme.bg

                                    ColumnLayout {
                                        id: findCol
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.top: parent.top
                                        anchors.margins: Theme.s3
                                        spacing: Theme.s1

                                        Header { text: "FINDINGS" }

                                        Repeater {
                                            model: auditBackend.findings
                                            Muted {
                                                Layout.fillWidth: true
                                                wrapMode: Text.WordWrap
                                                text: "* " + modelData
                                            }
                                        }
                                    }
                                }

                                // Level summary
                                Rectangle {
                                    Layout.fillWidth: true
                                    visible: !!auditBackend.summary
                                             && !!auditBackend.summary.levels
                                             && auditBackend.summary.levels.length > 0
                                    implicitHeight: lvlRow.implicitHeight + Theme.s3
                                    color: Theme.fg

                                    Row {
                                        id: lvlRow
                                        anchors.left: parent.left
                                        anchors.verticalCenter: parent.verticalCenter
                                        anchors.leftMargin: Theme.s3
                                        spacing: Theme.s4

                                        Repeater {
                                            model: auditBackend.summary.levels || []
                                            Column {
                                                spacing: 2
                                                T { text: modelData.name }
                                                Muted {
                                                    text: "bypass " + Math.round(modelData.bypassRate * 100) + "%  detected "
                                                          + Math.round(modelData.detectionRate * 100) + "%"
                                                }
                                                Muted {
                                                    visible: !!modelData.vendors
                                                    text: modelData.vendors
                                                    color: Theme.accent
                                                }
                                            }
                                        }
                                    }
                                }

                                // Outbound funnel card. Shown only when the run
                                // measured click-throughs, so an ordinary audit
                                // does not grow an empty panel.
                                Rectangle {
                                    id: funnelCard
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: funnelCol.implicitHeight + Theme.s3 * 2
                                    //: The funnel key is absent from a run that did
                                    //: not measure click-throughs, and reading
                                    //: through it warns on every summary refresh.
                                    //: Resolve it once, here.
                                    readonly property var f: auditBackend.summary
                                                             && auditBackend.summary.funnel
                                                             ? auditBackend.summary.funnel : ({})
                                    visible: f.enabled === true
                                    color: Theme.bg
                                    border.color: Theme.muted
                                    border.width: 1
                                    radius: Theme.s1

                                    ColumnLayout {
                                        id: funnelCol
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.top: parent.top
                                        anchors.margins: Theme.s3
                                        spacing: Theme.s1

                                        T {
                                            text: "Outbound funnel"
                                            color: Theme.accent
                                        }
                                        Muted {
                                            text: "Interaction rate " + (funnelCard.f.ratePct || 0)
                                                  + "%  clicks " + (funnelCard.f.clicks || 0)
                                                  + "  landed " + (funnelCard.f.landed || 0)
                                                  + "  engaged " + (funnelCard.f.engaged || 0)
                                        }
                                        Muted {
                                            text: "First-party " + (funnelCard.f.firstPartyClicks || 0)
                                                  + "  partner " + (funnelCard.f.partnerClicks || 0)
                                                  + "  refused " + (funnelCard.f.refused || 0)
                                                  + "  unreachable " + (funnelCard.f.unreachable || 0)
                                        }
                                        Muted {
                                            visible: funnelCard.f.dwellP50 !== undefined
                                                     && funnelCard.f.dwellP50 !== null
                                            text: "Dwell p50 " + (funnelCard.f.dwellP50 || 0) + "s "
                                                  + "(min " + (funnelCard.f.dwellMin || 0) + "s, "
                                                  + "max " + (funnelCard.f.dwellMax || 0) + "s)"
                                        }
                                        Repeater {
                                            model: funnelCard.f.destinations || []
                                            delegate: Muted {
                                                required property var modelData
                                                text: "→ " + modelData.url + "  (" + modelData.clicks + " click"
                                                      + (modelData.clicks === 1 ? "" : "s") + ")"
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                            }
                                        }
                                    }
                                }

                                // Visits table
                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    color: Theme.bg
                                    clip: true

                                    ListView {
                                        id: visitList
                                        anchors.fill: parent
                                        anchors.margins: Theme.s2
                                        clip: true
                                        model: auditBackend.visits
                                        boundsBehavior: Flickable.StopAtBounds
                                        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                                        delegate: Rectangle {
                                            // Declaring required properties opts out of the
                                            // implicit `index`/`model` context properties, so
                                            // `index` has to be requested explicitly.
                                            required property int index
                                            required property int visitorIndex
                                            required property string levelName
                                            required property string verdict
                                            required property var httpStatus
                                            required property string reason
                                            required property color verdictColor
                                            required property string source
                                            required property string proxyLabel

                                            width: visitList.width
                                            height: Theme.row
                                            color: index % 2 ? Theme.fg : "transparent"

                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.leftMargin: Theme.s2
                                                anchors.rightMargin: Theme.s2
                                                spacing: Theme.s2

                                                T {
                                                    text: "#" + visitorIndex
                                                    Layout.preferredWidth: Math.round(50 * Theme.scale)
                                                    color: Theme.muted
                                                }
                                                T {
                                                    text: levelName
                                                    Layout.preferredWidth: Math.round(150 * Theme.scale)
                                                    elide: Text.ElideRight
                                                }
                                                T {
                                                    text: verdict
                                                    color: verdictColor
                                                    Layout.preferredWidth: Math.round(90 * Theme.scale)
                                                }
                                                T {
                                                    text: httpStatus
                                                    Layout.preferredWidth: Math.round(40 * Theme.scale)
                                                    color: Theme.muted
                                                }
                                                T {
                                                    text: source
                                                    Layout.preferredWidth: Math.round(60 * Theme.scale)
                                                    color: Theme.dim
                                                }
                                                Muted {
                                                    Layout.fillWidth: true
                                                    text: reason
                                                    elide: Text.ElideRight
                                                }
                                            }
                                        }
                                    }
                                }

                                // Log
                                Rectangle {
                                    Layout.fillWidth: true
                                    implicitHeight: Math.round(96 * Theme.scale)
                                    color: Theme.fg
                                    Rule { anchors.top: parent.top }

                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: Theme.s2
                                        spacing: 0

                                        Header { text: "LOG" }

                                        Flickable {
                                            Layout.fillWidth: true
                                            Layout.fillHeight: true
                                            clip: true
                                            contentHeight: logCol.implicitHeight
                                            boundsBehavior: Flickable.StopAtBounds

                                            Column {
                                                id: logCol
                                                width: parent.width
                                                Repeater {
                                                    model: auditBackend.log
                                                    Muted {
                                                        width: logCol.width
                                                        text: modelData
                                                        elide: Text.ElideRight
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Status bar
        Rectangle {
            visible: tabs.currentIndex === 0
            Layout.fillWidth: true
            height: Theme.row
            color: Theme.fg

            Rule { anchors.top: parent.top }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.s3
                anchors.rightMargin: Theme.s3
                spacing: Theme.s2

                Btn {
                    visible: debugMode
                    text: "Refresh"
                    on: !backend.busy
                    onClicked: backend.refresh()
                }

                Btn {
                    icon: "\uE895"
                    text: "Sync Repos"
                    accent: Theme.accent
                    on: !backend.busy
                    onClicked: backend.sync()
                }

                Muted {
                    text: backend.lastSyncTime ? "Synced: " + backend.lastSyncTime : "Sync has not been ran yet."
                    visible: !backend.busy
                }

                Item { Layout.fillWidth: true }

                T {
                    visible: backend.statusText.length > 0
                    text: backend.statusText
                    color: backend.statusColor
                    Layout.maximumWidth: Math.round(200 * Theme.scale)
                    elide: Text.ElideRight
                }

                Row {
                    visible: backend.busy
                    spacing: Theme.s2

                    Progress {
                        width: Math.round(80 * Theme.scale)
                        value: backend.progress
                        active: backend.busy
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Btn {
                        text: "Cancel"
                        accent: Theme.err
                        onClicked: backend.cancelOperation()
                    }
                }

                T {
                    visible: backend.activeLabel.length > 0
                    text: backend.activeLabel
                    color: Theme.accent
                    Layout.maximumWidth: Math.round(200 * Theme.scale)
                    elide: Text.ElideRight
                }
            }
        }
    }
}

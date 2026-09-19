import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "theme"
import "components"
import "tabs"

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

    //: Index into the tab StackLayout. Owned by the tab bar so the highlight
    //: and the visible page cannot disagree; everything else switches pages
    //: through openTab().
    readonly property alias currentIndex: tabBar.active

    //: Jump to a tab by index. Kept as a function rather than letting callers
    //: assign currentIndex because a mis-set index leaves the bar highlighting
    //: a page that is not showing.
    function openTab(index) {
        if (index >= 0 && index < tabBar.count)
            tabBar.active = index
    }

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
                    id: tabBar
                    anchors.left: parent.left
                    anchors.leftMargin: Theme.s3
                    anchors.verticalCenter: parent.verticalCenter

                    //: The selected tab. The bar owns it because the bar is what
                    //: the user clicks; other pages read it through
                    //: root.currentIndex and switch through root.openTab().
                    property int active: 0
                    //: Read from the pages themselves, so adding a tab cannot
                    //: leave this count behind.
                    readonly property int count: tabs.count
                    readonly property var labels: ["Browsers", "GeoIP", "Info", "Audit", "Logs", "Reports"]

                Repeater {
                    model: tabBar.labels

                    Rectangle {
                        width: tabLbl.width + Theme.s4 * 2
                        height: Theme.row
                        color: "transparent"

                        T {
                            id: tabLbl
                            anchors.centerIn: parent
                            text: modelData
                            color: tabBar.active === index ? Theme.accent : Theme.muted
                        }

                        Rectangle {
                            anchors.bottom: parent.bottom
                            width: parent.width
                            height: Theme.s1 / 2
                            color: Theme.accent
                            visible: tabBar.active === index
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: root.openTab(index)
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
                visible: root.currentIndex === 0

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
                //: The bar owns the index; the stack follows it. Without this the
                //: highlight moves but the visible page never changes.
                currentIndex: tabBar.active

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
                AuditTab {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                }

                // Logs
                LogsTab {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                }

                // Reports
                ReportsTab {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                }
            }
        }

        // Status bar
        Rectangle {
            visible: root.currentIndex === 0
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

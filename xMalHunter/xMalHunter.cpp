#include "xMalHunter.h"
#include "PluginTabWidget.h"
#include "pluginmain.h"

#include <QFile>
static PluginTabWidget* pluginTabWidget;
static HANDLE hSetupEvent;
static HANDLE hStopEvent;

static QByteArray getResourceBytes(const char* path)
{
    QByteArray b;
    QFile s(path);
    if(s.open(QFile::ReadOnly))
        b = s.readAll();
    return b;
}

static QWidget* getParent()
{
    return QWidget::find((WId)Plugin::hwndDlg);
}

void xMalHunter::Init()
{
    hSetupEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
}

void xMalHunter::Setup()
{
    QWidget* parent = getParent();
    pluginTabWidget = new PluginTabWidget(parent);
    GuiAddQWidgetTab(pluginTabWidget);

    SetEvent(hSetupEvent);
}

void xMalHunter::WaitForSetup()
{
    WaitForSingleObject(hSetupEvent, INFINITE);
}

void xMalHunter::Stop()
{
    GuiCloseQWidgetTab(pluginTabWidget);
    pluginTabWidget->close();
    delete pluginTabWidget;

    SetEvent(hStopEvent);
}

void xMalHunter::WaitForStop()
{
    WaitForSingleObject(hStopEvent, INFINITE);
}

void xMalHunter::ShowTab()
{
    GuiShowQWidgetTab(pluginTabWidget);
}

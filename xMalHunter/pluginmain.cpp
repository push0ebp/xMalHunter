#include "pluginmain.h"
#include "xMalHunter.h"

#define plugin_name "xMalHunter"
#define plugin_version 1

int Plugin::handle;
HWND Plugin::hwndDlg;
int Plugin::hMenu;
int Plugin::hMenuDisasm;
int Plugin::hMenuDump;
int Plugin::hMenuStack;
int Plugin::hMenuGraph;
int Plugin::hMenuMemmap;
int Plugin::hMenuSymmod;

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = plugin_version;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, plugin_name);

    Plugin::handle = initStruct->pluginHandle;
    xMalHunter::Init();
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    Plugin::hwndDlg = setupStruct->hwndDlg;
    Plugin::hMenu = setupStruct->hMenu;
    Plugin::hMenuDisasm = setupStruct->hMenuDisasm;
    Plugin::hMenuDump = setupStruct->hMenuDump;
    Plugin::hMenuStack = setupStruct->hMenuStack;
    Plugin::hMenuGraph = setupStruct->hMenuGraph;
    Plugin::hMenuMemmap = setupStruct->hMenuMemmap;
    Plugin::hMenuSymmod = setupStruct->hMenuSymmod;
    GuiExecuteOnGuiThread(xMalHunter::Setup);
    xMalHunter::WaitForSetup();
}

extern "C" __declspec(dllexport) bool plugstop()
{
    GuiExecuteOnGuiThread(xMalHunter::Stop);
    xMalHunter::WaitForStop();
    return true;
}

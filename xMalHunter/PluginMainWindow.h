#ifndef PLUGINMAINWINDOW_H
#define PLUGINMAINWINDOW_H

#include <QMainWindow>
#include <Windows.h>

#include <xMalHunterCore.h>
namespace Ui {
class PluginMainWindow;
}

class PluginMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit PluginMainWindow(QWidget* parent = nullptr);
    ~PluginMainWindow();

private slots:
    void on_buttonScan_clicked();

    void on_tableModule_contextMenu();
    void on_tableModule_customContextMenuRequested(const QPoint &pos);

    void on_buttonDump_clicked();

    void resultTableDoubleClicked(int row, int column);
    void resultTableContextMenuRequested(const QPoint &pos);
    void tableBpShortcut();
private:
    void scan(DWORD pid);
    void dump();

    xMalHunter::Core::xMalHunter *xmalhunter;
    Ui::PluginMainWindow* ui;
};

#endif // PLUGINMAINWINDOW_H

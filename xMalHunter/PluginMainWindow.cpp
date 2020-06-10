#include "PluginMainWindow.h"
#include "ui_PluginMainWindow.h"

#include <algorithm>

#include <QMessageBox>
#include <QFileInfo>
#include <QFileDialog>
#include <QDebug>
#include <QShortcut>
#include <QtConcurrent/QtConcurrent>

#include "pe_sieve.h"


#include "scanners/code_scanner.h"
#include "scanners/iat_scanner.h"
#include "scanners/headers_scanner.h"
#include "scanners/workingset_scanner.h"
#include "scanners/artefact_scanner.h"
#include "postprocessors/results_dumper.h"

#include "postprocessors/pe_buffer.h"
#include "postprocessors/imp_rec/imp_reconstructor.h"
#include "postprocessors/pe_reconstructor.h"


#include <pluginsdk/_scriptapi_debug.h>
#include <pluginsdk/_scriptapi_gui.h>


#include <pluginsdk/_dbgfunctions.h>
#include <pluginsdk/bridgemain.h>
#include <pluginsdk/_scriptapi_module.h>

using namespace pesieve;


bool followDisassembly(ULONGLONG addr)
{
    DbgCmdExecDirect(QString("disasm " + QString::number(addr, 16)).toStdString().c_str());
    return true;
}

bool followDump(ULONGLONG addr)
{
    DbgCmdExecDirect(QString("dump " + QString::number(addr, 16)).toStdString().c_str());
    return true;
}

void follow(QTableWidget *table, int row, int column, int is_dump=0)
{
    auto item = table->item(row, column);
    if (!item) return;
    QString text = item->text();
    if (!text.size()) return;
    bool ok = false;
    ULONGLONG addr = text.toULongLong(&ok, 16);
    if (!ok) return;
    if(!DbgMemIsValidReadPtr(addr)) return;
    if (!is_dump)
        followDisassembly(addr);
    else
        followDump(addr);
}

void createConsole()
{
    if(AllocConsole())
    {
        FILE *file = nullptr;
        freopen_s(&file, "CONOUT$", "wb", stdout);
    }
}

PluginMainWindow::PluginMainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::PluginMainWindow), xmalhunter(NULL)
{
    ui->setupUi(this);
    auto allTables = {ui->tableInject, ui->tableHollow, ui->tableInline, ui->tablePatch, ui->tableShellcode, ui->tableIat, ui->tableModule};
    for (auto table :allTables) {
        for(int i=0;i<table->columnCount();i++) {
             table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        }
        table->horizontalHeader()->setStretchLastSection(true);
        connect(table, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(resultTableDoubleClicked(int, int)));
    }
    auto resultTables = {ui->tableInject, ui->tableHollow, ui->tableInline, ui->tablePatch, ui->tableShellcode, ui->tableIat};
    for (auto table : resultTables) {
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(table, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(resultTableContextMenuRequested(const QPoint&)));
        QShortcut* shortcut = new QShortcut(QKeySequence("F2"), table);
        connect(shortcut, SIGNAL(activated()), this, SLOT(tableBpShortcut()));
    }
}

PluginMainWindow::~PluginMainWindow()
{
    delete ui;
}

void PluginMainWindow::tableBpShortcut()
{
    if (!DbgIsDebugging()) return;
    auto shortcut = qobject_cast<QShortcut*>(sender());
    auto table = qobject_cast<QTableWidget*>(shortcut->parentWidget());
    if (!table) return;
    int row = table->currentRow();
    int column = table->currentColumn();
    if (!(row >= 0 && column >= 0)) return;
    QString text = table->item(row, column)->text();
    if (!text.size()) return;
    bool ok = false;
    ULONGLONG addr = text.toULongLong(&ok, 16);
    if (!ok) return;
    if(!DbgMemIsValidReadPtr(addr)) return;
    BPXTYPE bpType = DbgGetBpxTypeAt(addr);
    auto item = table->item(row, column);

    if (bpType == bp_none) {
        if(Script::Debug::SetBreakpoint(addr))
            item->setBackgroundColor(Qt::red);
    }
    else if ((bpType & bp_normal) == bp_normal)
    {
        Script::Debug::DeleteBreakpoint(addr);
        item->setBackgroundColor(Qt::white);

    }
}

void PluginMainWindow::resultTableDoubleClicked(int row, int column)
{
    auto table = qobject_cast<QTableWidget*>(sender());
    if (!table) return;
    follow(table, row, column);
}

void PluginMainWindow::resultTableContextMenuRequested(const QPoint &pos)
{

    QMenu contextMenu(this);

    QAction disassemblyAction("Follow in Disassembly", this);
    QAction dumpAction("Follow in Dump", this);
    contextMenu.addAction(&disassemblyAction);
    contextMenu.addAction(&dumpAction);
    auto table = qobject_cast<QTableWidget*>(sender());
    if (!table) return;
    QAction *selectedAction = contextMenu.exec(table->viewport()->mapToGlobal(pos));
    if (!selectedAction) return;
    bool is_dump = false;
    if (selectedAction->text() == disassemblyAction.text()) {
        is_dump = false;
    }
    else if (selectedAction->text() == dumpAction.text()) {
        is_dump = true;
    }
    if (table->rowCount())
        follow(table, table->currentRow(), table->currentColumn(), is_dump);
}

void addItem(QTableWidget *table, QStringList strs) {
   int index = table->rowCount();
    table->insertRow(index);
    for (int i = 0; i < strs.size(); i++)
    {
        table->setItem(index, i, new QTableWidgetItem(strs[i]));
        auto item = table->itemAt(i, index);
        if (!item) continue;
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    }

}

QString getAddressWithModule(ULONGLONG addr)
{
    char moduleName[64] = {0};
    QString module = QString::number(addr, 16);
    if(Script::Module::NameFromAddr(addr, moduleName))
    {
        module = moduleName;
        module += ":$";
        duint rva = addr - Script::Module::BaseFromAddr(addr);
        module += QString::number(rva, 16);
    }
    return module;
}

void PluginMainWindow::scan(DWORD pid )
{
    xmalhunter = new xMalHunter::Core::xMalHunter();
    xmalhunter->init(pid);
    try {
        xmalhunter->scan();

        // filter patches in breakpoints list
        BPMAP bpMap;
        DbgGetBpList(BPXTYPE::bp_normal, &bpMap);

        for (auto module_it = xmalhunter->suspicious_modules.begin(); module_it != xmalhunter->suspicious_modules.end(); ){
            auto module = *module_it;
            auto &patches = module->scan_report.patches;
            for(auto it = patches.begin(); it != patches.end(); )
            {
                auto patch = *it;
                bool is_bp = false;
                for (int i=0;i<bpMap.count; i++) {
                    if ( patch->getAddress() <= bpMap.bp[i].addr &&
                         bpMap.bp[i].addr <= patch->getAddress() + patch->getSize()) {
                        is_bp = true;
                        break;
                    }
                }
                if (is_bp)
                {
                    auto &total_patches = xmalhunter->scan_report.patches;
                    total_patches.erase(std::remove(total_patches.begin(), total_patches.end(), patch), total_patches.end());
                    it = patches.erase(it);
                }
                else {
                    it++;
                }
            }

            // if report is empty, delete module in module list;
            if (module->scan_report.isEmpty()) {
                  module_it = xmalhunter->suspicious_modules.erase(module_it);
            }
            else {
              module_it++;
            }
        }

        for (auto inject : xmalhunter->scan_report.injects) {
            addItem(ui->tableInject, {QString::number(inject->getInjectBase(), 16),
                                      QString::number(inject->getInjectSize(), 16) });
        }

        for (auto hollow : xmalhunter->scan_report.hollows) {
            addItem(ui->tableHollow, {QString::number(hollow->getRelocBase(), 16),
                                      QString::number(hollow->moduleSize, 16) });
        }

        for (auto shellcode : xmalhunter->scan_report.shellcodes) {
            char disasm[64] = {0};
            GuiGetDisassembly(shellcode->getRelocBase(), disasm);
            addItem(ui->tableShellcode, {QString::number(shellcode->getRelocBase(), 16),
                                         QString::number(shellcode->moduleSize, 16),
                                         QString(disasm)});
        }
        const int MAX_INLINE_HOOKS = 1000;
        int inline_hook_size = min(xmalhunter->scan_report.patches.size(), MAX_INLINE_HOOKS);

        for (auto module : xmalhunter->suspicious_modules) {
            int inline_hook_count = 0;
            for (auto inline_hook : module->scan_report.inline_hooks) {
                char disasm[64] = {0};
                GuiGetDisassembly(inline_hook->getAddress(), disasm);
                if (!inline_hook->isApiHooked() && inline_hook_count >= inline_hook_size)
                    continue;
                addItem(ui->tableInline, {QString::number(inline_hook->getAddress(), 16),
                                          getAddressWithModule(inline_hook->getAddress()),
                                          QString(inline_hook->getHookedFuncName().c_str()),
                                          QString(disasm),
                                          QString::number(inline_hook->getHookTargetVA(), 16),
                                          getAddressWithModule(inline_hook->getHookTargetVA()),
                                         });
                if (!inline_hook->getHookedFuncName().size())
                    inline_hook_count++;
            }
        }

        const int MAX_PATCHES = 1000;
        for (auto module : xmalhunter->suspicious_modules) {
            int patches_size = min(module->scan_report.patches.size(), MAX_PATCHES);

            for (int i = 0; i < patches_size; i++) {
                auto patch = xmalhunter->scan_report.patches.at(i);
                char disasm[64] = {0};
                GuiGetDisassembly(patch->getAddress(), disasm);

                const int MAX_BYTES_SIZE = 0x20;
                auto size = min(patch->getSize(), MAX_BYTES_SIZE);
                unsigned char bytes[MAX_BYTES_SIZE] = {0};
                DbgMemRead(patch->getAddress(), bytes, size);
                QStringList strBytes;
                for (int i = 0; i < size; i++)
                    strBytes << QString("%1").arg(bytes[i], 2, 16, QChar('0'));
                addItem(ui->tablePatch, {QString::number(patch->getAddress(), 16),
                                         getAddressWithModule(patch->getAddress()),
                                          QString::number(patch->getSize(), 16),
                                         QString(disasm),
                                         strBytes.join(' ')});
            }
            if (module->scan_report.patches.size() > MAX_PATCHES)
                addItem(ui->tablePatch, {"More", "...", "...", "..."});
        }

        for (auto iat_hook : xmalhunter->scan_report.iat_hooks) {
            addItem(ui->tableIat, {QString::number(iat_hook->getAddress(), 16),
                                   getAddressWithModule(iat_hook->getAddress()),
                                   QString(iat_hook->getFuncName().c_str()),
                                   QString::number(iat_hook->getTargetAddr(), 16)});
        }

        for (auto module : xmalhunter->suspicious_modules) {
            QString name = QFileInfo(QString(module->getFile().c_str())).fileName();
            if (!name.size())
            {
                QStringList inject_types;
                if (module->isInjected())
                    inject_types << "Inject";
                if (module->isHollowed())
                    inject_types << "Hollow";
                if (module->isShellcode())
                    inject_types << "Shellcode";
                name = inject_types.join(", ");
            }
            addItem(ui->tableModule, {name,
                                      QString::number(module->getAddress(), 16),
                                      QString::number(module->getSize(), 16),
                                      QString::number(module->scan_report.inline_hooks.size()),
                                      QString::number(module->scan_report.patches.size()),
                                      QString::number(module->scan_report.iat_hooks.size())});
        }
    }
    catch (std::exception &e) {
        e;
    }
    ui->buttonScan->setText("Scan");
}

void PluginMainWindow::dump()
{
    int currentRow = ui->tableModule->currentRow();
    if (currentRow == -1) {
        QMessageBox::critical(this, "Error", "Module not selected");
        return;
    }
    if (currentRow >=  (int)xmalhunter->suspicious_modules.size())
        return;
    auto module = xmalhunter->suspicious_modules.at(currentRow);
    auto dumpReport = new ModuleDumpReport(module->getAddress(), module->getSize());
    // get  file name of suspicious module
    QString filename;
    filename = QString::number(module->getAddress(), 16);

    QString moduleName = QFileInfo(QString(module->getFile().c_str())).fileName();
    if (moduleName.size())
        filename += "_" + moduleName;

    if (module->isInjected())
        filename += ".dll";
    else if (module->isShellcode())
        filename += ".bin";

    // get debuggee process directory path
    wchar_t dirPath[1024];
    GetModuleFileNameEx(xmalhunter->getProcessHandle(), NULL, dirPath, sizeof(dirPath)-1);
    QString strDirPath =  QFileInfo(QString::fromWCharArray(dirPath)).absolutePath();
    strDirPath += QDir::separator();
    strDirPath += filename;

    // show dialog
    QFileDialog dialog;
    dialog.setFileMode(QFileDialog::AnyFile);
    QString dumpFilename = dialog.getSaveFileName(NULL, "Save Dump", strDirPath,"All files (*)");
    xmalhunter->dumpModule(dumpFilename.toStdString(), module->report, dumpReport);

    if (dumpReport->isDumped) {
        QString msg = "Dumped to\n";
        msg += dumpFilename;
        QMessageBox::information(this, "Success", msg);
    }
    if (dumpReport->is_corrupt_pe)
        QMessageBox::critical(this, "Error", "Module not selected");

}

void PluginMainWindow::on_buttonScan_clicked()
{

    if (!DbgIsDebugging()) {
        QMessageBox::critical(this, "Error", "Debuggee not connected");
        return;
    }

    //clear result tables
    ui->tableInject->model()->removeRows(0, ui->tableInject->rowCount());
    ui->tableHollow->model()->removeRows(0, ui->tableHollow->rowCount());
    ui->tableInline->model()->removeRows(0, ui->tableInline->rowCount());
    ui->tablePatch->model()->removeRows(0, ui->tablePatch->rowCount());
    ui->tableShellcode->model()->removeRows(0, ui->tableShellcode->rowCount());
    ui->tableIat->model()->removeRows(0, ui->tableIat->rowCount());
    ui->tableModule->model()->removeRows(0, ui->tableModule->rowCount());
    ui->buttonScan->setText("Scanning");
    QtConcurrent::run(this, &PluginMainWindow::scan, DbgGetProcessId());
}


void PluginMainWindow::on_tableModule_customContextMenuRequested(const QPoint &pos)
{

    // show context menu
    QMenu contextMenu(this);

    QAction action("Dump", this);
    connect(&action, SIGNAL(triggered()), this, SLOT(on_tableModule_contextMenu()));
    contextMenu.addAction(&action);
    contextMenu.exec(ui->tableModule->viewport()->mapToGlobal(pos));
}

void PluginMainWindow::on_tableModule_contextMenu()
{
    dump();
}

void PluginMainWindow::on_buttonDump_clicked()
{
    dump();
}


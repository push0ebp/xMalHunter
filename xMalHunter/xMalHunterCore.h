#pragma once
#pragma comment(lib,"Advapi32.lib")

#include <peconv.h>

#include "pe_sieve.h"
#include "scanners/scanner.h"
#include "params_info/pe_sieve_params_info.h"


#include "scanners/code_scanner.h"
#include "scanners/iat_scanner.h"
#include "scanners/headers_scanner.h"
#include "scanners/workingset_scanner.h"
#include "scanners/artefact_scanner.h"
#include "postprocessors/results_dumper.h"

#include "postprocessors/pe_buffer.h"
#include "postprocessors/imp_rec/imp_reconstructor.h"
#include "postprocessors/pe_reconstructor.h"


#include "xMalHunterReport.h"

using namespace pesieve;
using namespace xMalHunter::Report;
namespace xMalHunter
{
    namespace Core {

        class SuspiciousModule {
        public:
            typedef enum {
                INJECT,
                HOLLOW,
                SHELLCODE,
                INLINE_HOOK,
                PATCH,
                IAT_HOOK
            } module_type;

            SuspiciousModule(ModuleScanReport *report) : report(report) {
                address = report->getRelocBase();
                size = report->moduleSize;
                file = report->moduleFile;
            }
            ULONGLONG getAddress() { return address; }
            size_t getSize() { return size; }
            std::string getFile() { return file; }
            bool isInjected() { return scan_report.injects.size() > 0; }
            bool isShellcode() { return scan_report.shellcodes.size() > 0; }
            bool isHollowed() { return scan_report.hollows.size() > 0; }

            ScanReport scan_report;
            ModuleScanReport *report;
        protected:
            ULONGLONG address;
            size_t size;
            std::string file;

        };


        class xMalHunter {
        public:
            bool initArgs(DWORD pid)
            {
                args.pid = pid;
                args.modules_filter = LIST_MODULES_ALL;
                args.imprec_mode = PE_IMPREC_AUTO;
                args.shellcode = true;
                args.iat = PE_IATS_FILTERED;
                return true;
            }

            xMalHunter() {}
            xMalHunter(DWORD pid) { init(pid); }

            xMalHunter(HANDLE hProcess) : hProcess(hProcess)
            {
                initArgs(GetProcessId(hProcess));
            }

            ~xMalHunter()
            {
                CloseHandle(hProcess);
            }

            bool init(DWORD pid)
            {
                if (hProcess) CloseHandle(hProcess);
                this->pid = pid;
                initArgs(pid);
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                return true;
            }


            ProcessReport* scan()
            {
                ProcessScanner scanner(hProcess, args);
                process_report = static_cast<ProcessReport*>(scanner.scanRemote());
                addSuspiciousModules();
                addTotalReports();
                return process_report;
            }
            bool addTotalReports()
            {
                for (auto suspicious_module : suspicious_modules)
                {
                    auto suspicious_scan_report = suspicious_module->scan_report;
                    scan_report.injects.insert(scan_report.injects.end(),
                        suspicious_scan_report.injects.begin(),
                        suspicious_scan_report.injects.end());
                    scan_report.hollows.insert(scan_report.hollows.end(),
                        suspicious_scan_report.hollows.begin(),
                        suspicious_scan_report.hollows.end());
                    scan_report.shellcodes.insert(scan_report.shellcodes.end(),
                        suspicious_scan_report.shellcodes.begin(),
                        suspicious_scan_report.shellcodes.end());
                    scan_report.inline_hooks.insert(scan_report.inline_hooks.end(),
                        suspicious_scan_report.inline_hooks.begin(),
                        suspicious_scan_report.inline_hooks.end());
                    scan_report.patches.insert(scan_report.patches.end(),
                        suspicious_scan_report.patches.begin(),
                        suspicious_scan_report.patches.end());
                    scan_report.iat_hooks.insert(scan_report.iat_hooks.end(),
                        suspicious_scan_report.iat_hooks.begin(),
                        suspicious_scan_report.iat_hooks.end());
                }
                return true;
            }


            bool addSuspiciousModules() {
                auto module_reports = process_report->module_reports;
                for (auto module_report : module_reports) {
                    if (ModuleScanReport::get_scan_status(module_report) != SCAN_SUSPICIOUS) continue;
                    if (!(module_report->getRelocBase() && module_report->moduleSize)) continue;

                    SuspiciousModule *suspicious_module = findSuspiciousModule(module_report);
                    if (!suspicious_module) {
                        suspicious_module = new SuspiciousModule(module_report);
                        suspicious_modules.push_back(suspicious_module);
                    }

                    if (dynamic_cast<WorkingSetScanReport*>(module_report)) {
                        auto report = static_cast<InjectReport*>(module_report);
                        if (report->isInjected())
                            suspicious_module->scan_report.injects.push_back(report);
                        if (report->isHollowed())
                            suspicious_module->scan_report.hollows.push_back(report);
                        if (report->isShellcode())
                            suspicious_module->scan_report.shellcodes.push_back(report);
                    }
                    if (dynamic_cast<CodeScanReport*>(module_report)) {
                        auto report = static_cast<PatchReport*>(module_report);
                        if (report->status != SCAN_SUSPICIOUS) continue;
                        auto patches = static_cast<std::vector<Patch*>>(report->getPatches());
                        for (auto patch : patches) {
                            if (patch->isHooked())
                                suspicious_module->scan_report.inline_hooks.push_back(patch);
                            else
                                suspicious_module->scan_report.patches.push_back(patch);
                        }
                    }
                    if (dynamic_cast<IATScanReport*>(module_report)) {

                        auto report = static_cast<IatReport*>(module_report);
                        if (report->status != SCAN_SUSPICIOUS) continue;
                        for (auto iat : report->notCovered.thunkToAddr) {
                            auto thunk_addr =  iat.first;
                            auto target_addr = iat.second;
                            auto func = report->storedFunc.find(thunk_addr)->second;
                            auto func_name = func.funcName;
                            auto iat_hook = new IatHook(report->getRelocBase(), func_name, thunk_addr, target_addr);
                            suspicious_module->scan_report.iat_hooks.push_back(iat_hook);
                        }
                    }

                }

                return true;
            }

            SuspiciousModule* findSuspiciousModule(ModuleScanReport *report) {
                auto it = std::find_if(suspicious_modules.begin(), suspicious_modules.end(),
                    [report](SuspiciousModule *module) {
                    return report->getRelocBase() == module->getAddress();
                });
                if (it == suspicious_modules.end())
                    return NULL;
                return *it;
            }

            bool dumpModule(std::string dumpFileName,
                IN ModuleScanReport* mod,
                OUT ModuleDumpReport *modDumpReport
            )
            {
                if (!mod) return nullptr;


                bool dump_shellcode = false;

                PeBuffer module_buf;
                bool is_corrupt_pe = false;
                ArtefactScanReport* artefactReport = dynamic_cast<ArtefactScanReport*>(mod);
                if (artefactReport) {
                    if (artefactReport->has_shellcode) {
                        dump_shellcode = true;
                    }
                    if (artefactReport->has_pe) {
                        PeReconstructor peRec(artefactReport->artefacts, module_buf);
                        if (!peRec.reconstruct(hProcess)) {
                            is_corrupt_pe = true;
                        }
                    }
                }
                if (!artefactReport || is_corrupt_pe) {
                    size_t img_size = mod->moduleSize;
                    if (img_size == 0) {
                        img_size = peconv::get_remote_image_size(hProcess, (BYTE*)mod->module);
                    }
                    module_buf.readRemote(hProcess, (ULONGLONG)mod->module, img_size);
                }

                modDumpReport->dumpFileName = dumpFileName;
                modDumpReport->is_corrupt_pe = is_corrupt_pe;
                modDumpReport->is_shellcode = !module_buf.isValidPe();

                peconv::ImpsNotCovered notCovered;

                if (module_buf.isFilled()) {

                    ImpReconstructor impRec(module_buf);
                    impRec.rebuildImportTable(process_report->exportsMap, pesieve::PE_IMPREC_AUTO);

                    module_buf.setRelocBase(mod->getRelocBase());
                    peconv::t_pe_dump_mode curr_dump_mode = peconv::PE_DUMP_AUTO;
                    modDumpReport->isDumped = module_buf.dumpPeToFile(modDumpReport->dumpFileName, curr_dump_mode, process_report->exportsMap, &notCovered);

                    if (!modDumpReport->isDumped) {
                        modDumpReport->isDumped = module_buf.dumpToFile(modDumpReport->dumpFileName);
                    }
                }

                return modDumpReport;
            }

            HANDLE getProcessHandle() { return hProcess;  }
            std::vector<SuspiciousModule*> suspicious_modules;
            ScanReport scan_report;
        protected:
            t_params args = { 0 };
            DWORD pid;
            HANDLE hProcess = 0;
            ProcessReport *process_report = NULL;


            std::vector<InjectReport*> inject_reports;
            std::vector<PatchReport*> patch_reports;
            std::vector<IatReport*> iat_reports;

        };
    }
}

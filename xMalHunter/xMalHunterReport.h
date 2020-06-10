#pragma once

namespace xMalHunter
{
	namespace Report {
		class Patch : public PatchList::Patch
		{
		public:
			bool isHooked()
			{
				return isHook;
			}

            bool isApiHooked()
            {
                return hooked_func.size() > 0;
            }

			ULONGLONG getAddress()
			{
				return (ULONGLONG)moduleBase + startRva;
			}

			ULONGLONG getModuleBase()
			{
				return (ULONGLONG)moduleBase;
			}


			ULONGLONG getSize()
			{
				return endRva - startRva;
			}

            ULONGLONG getStartRva()
            {
                return startRva;
            }

			std::string getHookedFuncName()
			{
				return hooked_func;
			}

			ULONGLONG getHookTargetModule()
			{
				return hookTargetModule;
			}

            ULONGLONG getHookTargetRva()
            {
                return hookTargetVA - hookTargetModule;
            }
		};

		class InjectReport : public WorkingSetScanReport {
		public:

			bool isInjected()
			{
				return has_pe && !is_listed_module;
			}

			bool isHollowed()
			{
				return has_pe && is_listed_module;
			}

			bool isShellcode()
			{
				return has_shellcode;
			}

			ArtefactScanReport* toArtefact()
			{
				return reinterpret_cast<ArtefactScanReport*>(this);

			}

			ULONGLONG getInjectBase()
			{
				auto artefact_report = toArtefact();
				return artefact_report ? getRelocBase() + artefact_report->artefacts.peBaseOffset : getRelocBase();
			}

			ULONGLONG getInjectSize()
			{
				auto artefact_report = toArtefact();
				return artefact_report ? artefact_report->artefacts.calculatedImgSize : moduleSize;
			}


		};

		class PatchReport :public CodeScanReport {
		public:
			std::vector<Patch*> getPatches()
			{
				return *reinterpret_cast<std::vector<Patch*>*>(&patchesList.patches);
			}
		};

		class IatReport : public IATScanReport {
		public:
			std::map<ULONGLONG, ULONGLONG> getHookedIats()
			{
				return notCovered.thunkToAddr;
			}
		};

		class IatHook {
		public:
			IatHook(ULONGLONG module_base, std::string func_name, ULONGLONG thunk_rva, ULONGLONG target_addr) :
				module_base(module_base), func_name(func_name), thunk_rva(thunk_rva), target_addr(target_addr)
			{

			}
			ULONGLONG getAddress() { return module_base + thunk_rva; }
			ULONGLONG getModuleBase() { return module_base; }
			ULONGLONG getThunkRva() { return thunk_rva; }
			ULONGLONG getTargetAddr() { return target_addr; }
			std::string getFuncName() { return func_name; }

		protected:
			ULONGLONG module_base;
			ULONGLONG thunk_rva, target_addr;
			std::string func_name;

		};
		class ScanReport
		{

		public:
            bool isEmpty() {
                return !injects.size() && !hollows.size() &&!shellcodes.size() &&
                    !inline_hooks.size() && !patches.size() &&
                    !iat_hooks.size();
            }

			std::vector<InjectReport*> injects, hollows, shellcodes;
			std::vector<Patch*> inline_hooks, patches;
			std::vector<IatHook*> iat_hooks;
		};


		class ProcessReport : public ProcessScanReport {
		public:
			std::set<ModuleScanReport*> getReports(t_report_type report_type)
			{
				return reportsByType[report_type];
			}

			std::set<ModuleScanReport*> getWorkingSetReports()
			{
				return reportsByType[REPORT_MEMPAGE_SCAN];
			}
			std::set<ModuleScanReport*> getCodeReports()
			{
				return reportsByType[REPORT_CODE_SCAN];
			}
			std::set<ModuleScanReport*> getIatReports()
			{
				return reportsByType[REPORT_IAT_SCAN];
			}
		};
	}
}

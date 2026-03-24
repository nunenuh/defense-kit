package system

// NewRootkitScannerWithAllPaths creates a RootkitScanner with fully injectable
// paths for testing: procModulesPath, sysModulePath, devPath, and procPath.
func NewRootkitScannerWithAllPaths(modulesPath, sysModulePath, devPath, procPath string) *RootkitScanner {
	return &RootkitScanner{
		procModulesPath: modulesPath,
		sysModulePath:   sysModulePath,
		devPath:         devPath,
		procPath:        procPath,
	}
}

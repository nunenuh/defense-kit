package timeline

// Exported shims for white-box testing of unexported helpers.

var (
	ParseTimestamp      = parseTimestamp
	ParsePIDFromLocation = parsePIDFromLocation
	ReadBootTime        = readBootTime
	NewLineScanner      = newLineScanner

	IsPersistenceEvent = isPersistenceEvent
	IsConnectionEvent  = isConnectionEvent
	IsCredentialEvent  = isCredentialEvent
	IsSUIDEvent        = isSUIDEvent
	IsUID0Event        = isUID0Event
)
